import http from "node:http";
import net from "node:net";
import { Writable } from "node:stream";
import express from "express";
import request from "supertest";
import pino from "pino";
import { ROOT_CONTEXT, trace } from "@opentelemetry/api";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { createHttpLogger, logger } from "../middleware/logger.js";
import { HTTP_LOG_REDACT_PATHS } from "../middleware/http-log-redaction.js";
import { firebaseOperatorPreAuthRequestHandler } from "../auth/firebase-operator-session-preflight.js";

const PUBLIC = "https://paperclip.example.test";
const LAB = "https://paperclip.lab.example.test";
const PATH = "/api/auth/firebase-session/begin";
const EXCHANGE = "/api/auth/firebase-session/exchange";
const JSON_TYPE = "application/json";
const QUERY_TOKEN = "PREFLIGHT-QUERY-TOKEN-SENTINEL";
const QUERY_STATE = "PREFLIGHT-QUERY-STATE-SENTINEL";
const BODY_STATE = "PREFLIGHT-BODY-STATE-SENTINEL";
const HEADER_SENTINEL = "PREFLIGHT-HEADER-SENTINEL";

type CapturedSpan = {
  name: string;
  parent: unknown;
  attributes: Record<string, unknown>;
  ended: boolean;
};
const spans: CapturedSpan[] = [];
let tracerThrows = false;
const recordingTracer = {
  startSpan(name: string, options?: { attributes?: Record<string, unknown> }, parent?: unknown) {
    if (tracerThrows) throw new Error("PREFLIGHT-TRACE-FAIL-SENTINEL");
    const span: CapturedSpan = { name, parent, attributes: { ...(options?.attributes ?? {}) }, ended: false };
    spans.push(span);
    return {
      setAttribute(key: string, value: unknown) { span.attributes[key] = value; return this; },
      end() { span.ended = true; },
    };
  },
};
const recordingProvider = { getTracer: () => recordingTracer };

function appFor(options: {
  maxBodyBytes?: number;
  origins?: string[];
  logs?: string[];
  sdkError?: string;
  audit?: (event: unknown) => void;
  downstreamCalls?: string[];
  globalParserFirst?: boolean;
} = {}) {
  const app = express();
  if (options.logs) {
    const stream = new Writable({ write(chunk, _encoding, callback) { options.logs!.push(chunk.toString()); callback(); } });
    app.use(createHttpLogger(pino({ level: "trace", redact: [...HTTP_LOG_REDACT_PATHS] }, stream)));
  }
  if (options.globalParserFirst) app.use(express.json({ limit: "10mb" }));
  app.use(firebaseOperatorPreAuthRequestHandler({
    trustedOrigins: new Set(options.origins ?? [PUBLIC, LAB]),
    ...(options.maxBodyBytes ? { maxBodyBytes: options.maxBodyBytes } : {}),
    ...(options.audit ? { audit: options.audit } : {}),
  } as never));
  app.post([PATH, EXCHANGE], (req, res, next) => {
    options.downstreamCalls?.push(`${req.method} ${req.originalUrl}`);
    if (options.sdkError) {
      const error = new Error(options.sdkError);
      (res as express.Response & { err?: Error }).err = error;
      next(error);
      return;
    }
    res.status(200).json({ method: req.method, path: req.path, body: req.body ?? null });
  });
  app.all("/api/auth/*splat", (_req, res) => res.status(418).json({ ordinaryAuth: true }));
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(options.sdkError ? 500 : 413).json({ error: options.sdkError ? "internal error" : "body rejected" });
  });
  return app;
}

function assertObservedDenial(input: {
  events: unknown[];
  expectedReason: string;
  response: request.Response;
  expectedStatus?: number;
  logLines?: string[];
  sentinels?: string[];
}) {
  expect.soft(input.events).toHaveLength(1);
  const event = (input.events[0] ?? {}) as Record<string, unknown>;
  expect.soft(event).toMatchObject({ event: "preflight", outcome: "denied", reason: input.expectedReason });
  expect.soft(Object.keys(event).sort()).toEqual(["correlationId", "event", "outcome", "reason"]);
  expect.soft(event.correlationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  expect.soft(spans).toHaveLength(1);
  expect.soft(spans[0]?.name).toBe("firebase.operator_session.preflight");
  expect.soft(spans[0]?.parent).toBe(ROOT_CONTEXT);
  expect.soft(spans[0]?.ended).toBe(true);
  expect.soft(spans[0]?.attributes).toEqual({
    "firebase_operator.outcome": "denied",
    "firebase_operator.reason": input.expectedReason,
  });
  if (input.expectedStatus !== undefined) expect.soft(input.response.status).toBe(input.expectedStatus);
  expect.soft(input.response.body).toEqual({ error: "Request rejected" });
  const surface = JSON.stringify({ event, span: spans[0], logs: input.logLines ?? [], body: input.response.body, headers: input.response.headers });
  for (const sentinel of input.sentinels ?? []) expect.soft(surface).not.toContain(sentinel);
}

describe("Firebase operator pre-auth HTTP boundary", () => {
  const servers: http.Server[] = [];
  beforeAll(() => {
    expect(trace.setGlobalTracerProvider(recordingProvider as never)).toBe(true);
  });
  afterAll(() => {
    trace.disable();
  });
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))));
    spans.length = 0;
    tracerThrows = false;
    vi.restoreAllMocks();
  });

  it("passes only exact POST routes when raw Host authority and exact HTTPS Origin map together", async () => {
    const app = appFor();
    const accepted = await request(app).post(PATH).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send({});
    expect(accepted.status).toBe(200);
    expect(accepted.body).toMatchObject({ method: "POST", path: PATH, body: {} });
    const lab = await request(app).post(EXCHANGE).set("Host", new URL(LAB).host).set("Origin", LAB).set("Content-Type", JSON_TYPE).send({ transactionId: "tx", state: "s" });
    expect(lab.status).toBe(200);
  });

  it.each([
    ["foreign origin", "https://attacker.example.test", new URL(PUBLIC).host],
    ["URL credentials in origin", "https://user:password@paperclip.example.test", new URL(PUBLIC).host],
    ["public origin on lab host", PUBLIC, new URL(LAB).host],
    ["lab origin on public host", LAB, new URL(PUBLIC).host],
    ["null origin", "null", new URL(PUBLIC).host],
    ["missing origin", undefined, new URL(PUBLIC).host],
  ])("rejects %s without CORS credential headers", async (_label, origin, host) => {
    let call = request(appFor()).post(PATH).set("Host", host).set("Content-Type", JSON_TYPE).send({});
    if (origin) call = call.set("Origin", origin);
    const response = await call;
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(response.headers["access-control-allow-credentials"]).toBeUndefined();
    expect(response.headers["access-control-allow-origin"]).toBeUndefined();
  });

  it("ignores forwarding headers and refuses host/origin spoof combinations", async () => {
    const accepted = await request(appFor()).post(PATH)
      .set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC)
      .set("X-Forwarded-Host", new URL(LAB).host).set("X-Forwarded-Proto", "https")
      .set("Content-Type", JSON_TYPE).send({});
    expect(accepted.status).toBe(200);
    const rejected = await request(appFor()).post(PATH)
      .set("Host", "attacker.example.test").set("Origin", PUBLIC)
      .set("X-Forwarded-Host", new URL(PUBLIC).host).set("X-Forwarded-Proto", "https")
      .set("Content-Type", JSON_TYPE).send({});
    expect(rejected.status).toBeGreaterThanOrEqual(400);
  });

  it.each([
    ["GET", PATH], ["OPTIONS", PATH], ["POST", `${PATH}/`], ["POST", `${PATH}?next=/`],
    ["POST", "/api/auth/Firebase-session/begin"], ["PUT", EXCHANGE],
  ])("does not treat %s %s as a Firebase pre-auth request", async (method, path) => {
    const call = request(appFor())[method.toLowerCase() as "get" | "post" | "put"](path);
    const response = await call.set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send({});
    expect(response.status).not.toBe(200);
    expect(response.headers["access-control-allow-credentials"]).toBeUndefined();
  });

  it.each([
    ["text/plain", { "Content-Type": "text/plain" }],
    ["missing content type", {}],
    ["invalid JSON", { "Content-Type": JSON_TYPE }],
  ])("rejects %s before endpoint dispatch", async (_label, headers) => {
    const response = await request(appFor()).post(PATH).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC).set(headers).send(_label === "invalid JSON" ? "{" : "{}");
    expect(response.status).toBeGreaterThanOrEqual(400);
  });

  it("accepts exactly 4096 JSON bytes and rejects 4097 for fixed-length and chunked bodies", async () => {
    const app = appFor();
    const exactBody = JSON.stringify({ value: "x".repeat(4084) });
    const oversizedBody = JSON.stringify({ value: "x".repeat(4085) });
    expect(Buffer.byteLength(exactBody)).toBe(4096);
    expect(Buffer.byteLength(oversizedBody)).toBe(4097);
    const exact = await request(app).post(PATH).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send(exactBody);
    expect(exact.status).toBe(200);
    const fixed = await request(app).post(PATH).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send(oversizedBody);
    expect(fixed.status).toBe(413);

    const server = http.createServer(app);
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as import("node:net").AddressInfo).port;
    const sendChunked = (body: string) => new Promise<number>((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port, method: "POST", path: PATH, headers: { Host: new URL(PUBLIC).host, Origin: PUBLIC, "Content-Type": JSON_TYPE, "Transfer-Encoding": "chunked" } }, (res) => {
        res.resume(); res.on("end", () => resolve(res.statusCode ?? 0));
      });
      req.on("error", reject);
      req.write(body.slice(0, 2000));
      req.write(body.slice(2000, 4000));
      req.end(body.slice(4000));
    });
    const exactChunked = await sendChunked(exactBody);
    expect(exactChunked).toBe(200);
    const chunked = await sendChunked(oversizedBody);
    expect(chunked).toBe(413);
  });

  it("rejects raw duplicate Origin, Host, Authorization, Content-Type, and ambiguous CL+TE framing", async () => {
    const server = http.createServer(appFor());
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as import("node:net").AddressInfo).port;
    // Node's client normalizes object headers, so write the field sequence on a raw socket.
    const rawSocket = (fields: string[]) => new Promise<number>((resolve, reject) => {
      const socket = net.connect(port, "127.0.0.1", () => {
        socket.write(`POST ${PATH} HTTP/1.1\r\n${fields.join("\r\n")}\r\n\r\n{}\r\n`);
      });
      let data = "";
      socket.on("data", (chunk: Buffer) => { data += chunk.toString(); });
      socket.on("end", () => resolve(Number(data.match(/^HTTP\/1\.1 (\d+)/)?.[1] ?? 0)));
      socket.on("error", reject);
    });
    const base = [`Host: ${new URL(PUBLIC).host}`, `Origin: ${PUBLIC}`, `Content-Type: ${JSON_TYPE}`, "Content-Length: 2", "Connection: close"];
    const cases = [
      [...base, `Origin: ${PUBLIC}`],
      [...base, `Host: ${new URL(PUBLIC).host}`],
      [...base, "Authorization: Bearer one", "Authorization: Bearer two"],
      [...base, `Content-Type: ${JSON_TYPE}`],
      [...base, "Content-Length: 2"],
      [...base, "Transfer-Encoding: chunked"],
    ];
    for (const fields of cases) expect(await rawSocket(fields)).toBeGreaterThanOrEqual(400);
  });

  it("keeps unrelated auth paths in the normal middleware flow and rate-limits by socket IP", async () => {
    const app = appFor();
    const unrelated = await request(app).post("/api/auth/sign-in/email").set("Origin", PUBLIC).send({});
    expect(unrelated.status).toBe(418);
    const limited = appFor();
    let last = 0;
    for (let i = 0; i < 12; i += 1) {
      last = (await request(limited).post(PATH).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send({})).status;
    }
    expect(last).toBe(429);

    const exchangeLimited = appFor();
    for (let i = 0; i < 21; i += 1) {
      last = (await request(exchangeLimited).post(EXCHANGE).set("Host", new URL(PUBLIC).host)
        .set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send({ transactionId: "unused", state: "unused" })).status;
    }
    expect(last).toBe(429);
  });

  it("logs reserved auth namespace failures as a fixed route without inputs, parser data, or SDK error prose", async () => {
    const logLines: string[] = [];
    const app = appFor({ logs: logLines, sdkError: "RAW-SDK-ERROR-SENTINEL" });
    const inputSentinels = [
      "STATE-BODY-SENTINEL",
      "UNKNOWN-CREDENTIAL-ALIAS-SENTINEL",
      "TRANSACTION-ID-SENTINEL",
      "COOKIE-INPUT-SENTINEL",
      "AUTH-HEADER-SENTINEL",
      "QUERY-CREDENTIAL-SENTINEL",
      "PARSER-BUFFER-SENTINEL",
      "RAW-SDK-ERROR-SENTINEL",
    ];
    const host = new URL(PUBLIC).host;
    const malformed = await request(app).post(EXCHANGE).set("Host", host).set("Origin", PUBLIC)
      .set("Content-Type", JSON_TYPE).send('{"value":"PARSER-BUFFER-SENTINEL');
    expect(malformed.status).toBeGreaterThanOrEqual(400);
    await request(app).get(`${EXCHANGE}?token=QUERY-CREDENTIAL-SENTINEL`)
      .set("Host", host).set("Origin", PUBLIC).expect((response) => { expect(response.status).toBeGreaterThanOrEqual(400); });
    await request(app).post(`${EXCHANGE}/`).set("Host", host).set("Origin", PUBLIC)
      .set("Content-Type", JSON_TYPE).send({ state: inputSentinels[0] });
    await request(app).post("/api/auth/firebase-session/unknown-suffix?credential=QUERY-CREDENTIAL-SENTINEL")
      .set("Host", host).set("Origin", PUBLIC).set("Content-Type", JSON_TYPE)
      .send({ transactionId: inputSentinels[2], credentialAlias: inputSentinels[1] });
    await request(app).post("/api/auth/FIREBASE-SESSION/exchange").set("Host", host).set("Origin", PUBLIC)
      .set("Content-Type", JSON_TYPE).set("Authorization", `Bearer ${inputSentinels[4]}`)
      .set("Cookie", `probe=${inputSentinels[3]}`).send({ state: inputSentinels[0] });
    await request(app).post(EXCHANGE).set("Host", host).set("Origin", PUBLIC).set("Content-Type", JSON_TYPE)
      .send({ state: inputSentinels[0], credentialAlias: inputSentinels[1] });

    const combinedLogs = logLines.join("\n");
    const records = logLines.map((line) => JSON.parse(line) as {
      req?: { method?: string; url?: string; headers?: unknown; query?: unknown; body?: unknown; params?: unknown };
      res?: { statusCode?: number; headers?: unknown };
      msg?: string;
      err?: unknown;
    });
    expect(records.length).toBeGreaterThanOrEqual(6);
    for (const record of records) {
      expect(record.req?.url).toBe("/api/auth/firebase-session/:reserved");
      expect(["GET", "POST"]).toContain(record.req?.method);
      expect(record.res?.statusCode).toBeGreaterThanOrEqual(400);
      expect(record.req?.headers).toBeUndefined();
      expect(record.req?.query).toBeUndefined();
      expect(record.req?.body).toBeUndefined();
      expect(record.req?.params).toBeUndefined();
      expect(record.res?.headers).toBeUndefined();
      expect(record.err).toBeUndefined();
    }
    expect(records.some((record) => record.msg?.includes("/api/auth/firebase-session/:reserved"))).toBe(true);
    for (const sentinel of inputSentinels) expect(combinedLogs).not.toContain(sentinel);
    expect(combinedLogs).toContain("/api/auth/firebase-session/:reserved");
    expect(combinedLogs).toMatch(/"statusCode":(?:400|405|418|500)/);
    expect(combinedLogs).toMatch(/"method":"(?:GET|POST)"/);
    expect(combinedLogs).not.toContain("/exchange/");
    expect(combinedLogs).not.toContain("unknown-suffix");
    expect(combinedLogs).not.toContain("FIREBASE-SESSION");
  });

  it("audits and records one safe ROOT_CONTEXT span for each reserved-path denial", async () => {
    const events: unknown[] = [];
    const logLines: string[] = [];
    const downstreamCalls: string[] = [];
    const app = appFor({ audit: (event) => events.push(event), logs: logLines, downstreamCalls });
    const requestCases: Array<{
      label: string;
      expectedStatus: number;
      expectedReason: string;
      send: () => Promise<request.Response>;
    }> = [
      {
        label: "query credential",
        expectedStatus: 404,
        expectedReason: "bad_request",
        send: () => request(app).post(`${EXCHANGE}?credential=${QUERY_TOKEN}&state=${QUERY_STATE}`)
          .set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send({}),
      },
      {
        label: "foreign Origin",
        expectedStatus: 403,
        expectedReason: "origin_denied",
        send: () => request(app).post(PATH).set("Host", new URL(PUBLIC).host)
          .set("Origin", "https://attacker.example.test").set("Content-Type", JSON_TYPE).send({}),
      },
      {
        label: "null Origin",
        expectedStatus: 403,
        expectedReason: "origin_denied",
        send: () => request(app).post(PATH).set("Host", new URL(PUBLIC).host)
          .set("Origin", "null").set("Content-Type", JSON_TYPE).send({}),
      },
      {
        label: "missing Origin",
        expectedStatus: 400,
        expectedReason: "origin_denied",
        send: () => request(app).post(PATH).set("Host", new URL(PUBLIC).host).set("Content-Type", JSON_TYPE).send({}),
      },
      {
        label: "mismatched Host and Origin",
        expectedStatus: 403,
        expectedReason: "origin_denied",
        send: () => request(app).post(PATH).set("Host", new URL(LAB).host)
          .set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send({}),
      },
      {
        label: "wrong method",
        expectedStatus: 405,
        expectedReason: "bad_request",
        send: () => request(app).get(PATH).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC).set("Content-Type", JSON_TYPE),
      },
      {
        label: "case variant",
        expectedStatus: 404,
        expectedReason: "bad_request",
        send: () => request(app).post("/api/auth/Firebase-session/begin").set("Host", new URL(PUBLIC).host)
          .set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send({}),
      },
      {
        label: "trailing slash",
        expectedStatus: 404,
        expectedReason: "bad_request",
        send: () => request(app).post(`${PATH}/`).set("Host", new URL(PUBLIC).host)
          .set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send({}),
      },
      {
        label: "unknown namespace suffix",
        expectedStatus: 404,
        expectedReason: "bad_request",
        send: () => request(app).post("/api/auth/firebase-session/unknown-suffix").set("Host", new URL(PUBLIC).host)
          .set("Origin", PUBLIC).set("Content-Type", JSON_TYPE).send({ state: BODY_STATE }),
      },
      {
        label: "unsupported Content-Type",
        expectedStatus: 415,
        expectedReason: "bad_request",
        send: () => request(app).post(PATH).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC)
          .set("Content-Type", "text/plain").send("{}"),
      },
      {
        label: "malformed JSON",
        expectedStatus: 400,
        expectedReason: "bad_request",
        send: () => request(app).post(PATH).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC)
          .set("Content-Type", JSON_TYPE).send(`{"state":"${BODY_STATE}"`),
      },
      {
        label: "oversized fixed-length body",
        expectedStatus: 413,
        expectedReason: "bad_request",
        send: () => request(app).post(PATH).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC)
          .set("Content-Type", JSON_TYPE).send(JSON.stringify({ value: "x".repeat(4085) })),
      },
    ];
    const correlations: string[] = [];
    for (const scenario of requestCases) {
      events.length = 0;
      spans.length = 0;
      const response = await scenario.send();
      assertObservedDenial({
        events,
        expectedReason: scenario.expectedReason,
        response,
        expectedStatus: scenario.expectedStatus,
        logLines,
        sentinels: [QUERY_TOKEN, QUERY_STATE, BODY_STATE, HEADER_SENTINEL],
      });
      correlations.push((events[0] as { correlationId: string } | undefined)?.correlationId ?? "");
      expect(downstreamCalls).toHaveLength(0);
    }
    expect.soft(new Set(correlations).size).toBe(correlations.length);
    const combinedLogs = logLines.join("\n");
    for (const sentinel of [QUERY_TOKEN, QUERY_STATE, BODY_STATE, HEADER_SENTINEL]) expect(combinedLogs).not.toContain(sentinel);
  });

  it("audits raw duplicate fields and chunked size denials before downstream dispatch", async () => {
    const events: unknown[] = [];
    const logs: string[] = [];
    const downstreamCalls: string[] = [];
    const server = http.createServer(appFor({ audit: (event) => events.push(event), logs, downstreamCalls }));
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as import("node:net").AddressInfo).port;
    const rawSocket = (fields: string[], body = "{}", protocol = "HTTP/1.1") => new Promise<{ status: number; text: string }>((resolve, reject) => {
      const socket = net.connect(port, "127.0.0.1", () => {
        socket.write(`POST ${PATH} ${protocol}\r\n${fields.join("\r\n")}\r\n\r\n${body}`);
      });
      let text = "";
      socket.on("data", (chunk: Buffer) => { text += chunk.toString(); });
      socket.on("end", () => resolve({ status: Number(text.match(/^HTTP\/1\.[01] (\d+)/)?.[1] ?? 0), text }));
      socket.on("error", reject);
    });
    const base = [`Host: ${new URL(PUBLIC).host}`, `Origin: ${PUBLIC}`, `Content-Type: ${JSON_TYPE}`, "Content-Length: 2", "Connection: close"];
    const duplicateCases = [
      [...base, `Origin: ${PUBLIC}`],
      [...base, `Host: ${new URL(PUBLIC).host}`],
      [...base, `Authorization: Bearer ${HEADER_SENTINEL}`, "Authorization: Bearer second"],
      [...base, `Content-Type: ${JSON_TYPE}`],
    ];
    for (const fields of duplicateCases) {
      events.length = 0;
      spans.length = 0;
      const response = await rawSocket(fields);
      const [rawHeaders, rawBody = ""] = response.text.split("\r\n\r\n");
      const parsedHeaders = Object.fromEntries((rawHeaders ?? "").split("\r\n").slice(1).map((line) => {
        const colon = line.indexOf(":");
        return [line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()];
      }));
      const responseLike = {
        status: response.status,
        body: JSON.parse(rawBody),
        headers: parsedHeaders,
      } as request.Response;
      assertObservedDenial({
        events,
        expectedReason: "bad_request",
        response: responseLike,
        expectedStatus: 400,
        logLines: logs,
        sentinels: [HEADER_SENTINEL],
      });
      expect(downstreamCalls).toHaveLength(0);
    }

    events.length = 0;
    spans.length = 0;
    const missingHostFields = [`Origin: ${PUBLIC}`, `Content-Type: ${JSON_TYPE}`, "Content-Length: 2", "Connection: close"];
    const missingHostResponse = await rawSocket(missingHostFields, "{}", "HTTP/1.0");
    const [missingHostHeaders, missingHostBody = ""] = missingHostResponse.text.split("\r\n\r\n");
    const missingHostParsedHeaders = Object.fromEntries((missingHostHeaders ?? "").split("\r\n").slice(1).map((line) => {
      const colon = line.indexOf(":");
      return [line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()];
    }));
    assertObservedDenial({
      events,
      expectedReason: "origin_denied",
      response: {
        status: missingHostResponse.status,
        body: JSON.parse(missingHostBody),
        headers: missingHostParsedHeaders,
      } as request.Response,
      expectedStatus: 400,
      logLines: logs,
    });
    expect(downstreamCalls).toHaveLength(0);

    events.length = 0;
    spans.length = 0;
    const chunked = JSON.stringify({ value: `${BODY_STATE}${"x".repeat(4085)}` });
    const chunkedResponse = await new Promise<{ status: number; text: string; headers: Record<string, string | string[] | undefined> }>((resolve, reject) => {
      const req = http.request({
        host: "127.0.0.1", port, method: "POST", path: PATH,
        headers: { Host: new URL(PUBLIC).host, Origin: PUBLIC, "Content-Type": JSON_TYPE, "Transfer-Encoding": "chunked" },
      }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString(), headers: res.headers }));
      });
      req.on("error", reject);
      req.write(chunked.slice(0, 2000));
      req.write(chunked.slice(2000, 4000));
      req.end(chunked.slice(4000));
    });
    assertObservedDenial({
      events,
      expectedReason: "bad_request",
      response: { status: chunkedResponse.status, body: JSON.parse(chunkedResponse.text), headers: chunkedResponse.headers } as request.Response,
      expectedStatus: 413,
      logLines: logs,
      sentinels: [BODY_STATE],
    });
    expect(downstreamCalls).toHaveLength(0);
  });

  it("audits already-parsed missing-capture and rate denials without duplicate success events", async () => {
    const events: unknown[] = [];
    const downstreamCalls: string[] = [];
    const app = appFor({ audit: (event) => events.push(event), downstreamCalls, globalParserFirst: true });
    const oversizedValid = `${JSON.stringify({ transactionId: "tx", state: BODY_STATE })}${" ".repeat(5000)}`;
    const parsed = await request(app).post(EXCHANGE).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC)
      .set("Content-Type", JSON_TYPE).send(oversizedValid);
    assertObservedDenial({
      events,
      expectedReason: "bad_request",
      response: parsed,
      expectedStatus: 400,
      sentinels: [BODY_STATE],
    });
    expect(downstreamCalls).toHaveLength(0);

    events.length = 0;
    spans.length = 0;
    const limitedEvents: unknown[] = [];
    const calls: string[] = [];
    const limited = appFor({ audit: (event) => limitedEvents.push(event), downstreamCalls: calls });
    let final: request.Response | undefined;
    for (let i = 0; i < 11; i += 1) {
      final = await request(limited).post(PATH).set("Host", new URL(PUBLIC).host).set("Origin", PUBLIC)
        .set("Content-Type", JSON_TYPE).send({});
      if (i < 10) expect(final.status).toBe(200);
    }
    expect.soft(final?.status).toBe(429);
    expect.soft(calls).toHaveLength(10);
    expect.soft(limitedEvents).toHaveLength(1);
    expect.soft(limitedEvents[0]).toMatchObject({ event: "preflight", outcome: "denied", reason: "rate_limited" });
    expect.soft(spans).toHaveLength(1);
    expect.soft(spans[0]).toMatchObject({ name: "firebase.operator_session.preflight", parent: ROOT_CONTEXT, ended: true });
  });

  it("uses the default Pino audit sink for preflight denials", async () => {
    const spies = ["debug", "info", "warn", "error"].map((level) => vi.spyOn(logger, level as "warn").mockImplementation(() => undefined as never));
    try {
      const app = appFor();
      const response = await request(app).post(PATH).set("Host", new URL(PUBLIC).host)
        .set("Origin", "https://attacker.example.test").set("Content-Type", JSON_TYPE).send({ state: BODY_STATE });
      expect.soft(response.status).toBe(403);
      const calls = spies.flatMap((spy) => spy.mock.calls);
      expect.soft(calls).toHaveLength(1);
      expect.soft(JSON.stringify(calls)).toContain("preflight");
      expect.soft(JSON.stringify(calls)).toContain("origin_denied");
      expect.soft(JSON.stringify(calls)).not.toContain(BODY_STATE);
      expect.soft(spans).toHaveLength(1);
      expect.soft(spans[0]).toMatchObject({ name: "firebase.operator_session.preflight", parent: ROOT_CONTEXT, ended: true });
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });

  it("preserves denial responses when injected audit and tracer sinks throw", async () => {
    let auditCalls = 0;
    const auditDownstream: string[] = [];
    const auditLogs: string[] = [];
    const auditApp = appFor({
      audit: () => { auditCalls += 1; throw new Error("PREFLIGHT-AUDIT-FAIL-SENTINEL"); },
      downstreamCalls: auditDownstream,
      logs: auditLogs,
    });
    const auditResponse = await request(auditApp).post(PATH).set("Host", new URL(PUBLIC).host)
      .set("Origin", "https://attacker.example.test").set("Content-Type", JSON_TYPE).send({ state: BODY_STATE });
    expect.soft(auditResponse.status).toBe(403);
    expect.soft(auditResponse.body).toEqual({ error: "Request rejected" });
    expect.soft(auditCalls).toBe(1);
    expect.soft(auditDownstream).toHaveLength(0);
    expect.soft(spans).toHaveLength(1);
    expect.soft(JSON.stringify({ response: auditResponse.body, headers: auditResponse.headers, logs: auditLogs }))
      .not.toContain("PREFLIGHT-AUDIT-FAIL-SENTINEL");

    spans.length = 0;
    tracerThrows = true;
    const traceEvents: unknown[] = [];
    const traceDownstream: string[] = [];
    const traceLogs: string[] = [];
    const traceApp = appFor({ audit: (event) => traceEvents.push(event), downstreamCalls: traceDownstream, logs: traceLogs });
    const traceResponse = await request(traceApp).post(PATH).set("Host", new URL(PUBLIC).host)
      .set("Origin", "https://attacker.example.test").set("Content-Type", JSON_TYPE).send({ state: BODY_STATE });
    expect.soft(traceResponse.status).toBe(403);
    expect.soft(traceResponse.body).toEqual({ error: "Request rejected" });
    expect.soft(traceEvents).toHaveLength(1);
    expect.soft(traceDownstream).toHaveLength(0);
    expect.soft(spans).toHaveLength(0);
    const traceSurface = JSON.stringify({ events: traceEvents, body: traceResponse.body, headers: traceResponse.headers, logs: traceLogs });
    expect.soft(traceSurface).not.toContain("PREFLIGHT-TRACE-FAIL-SENTINEL");
    expect.soft(traceSurface).not.toContain(BODY_STATE);
  });
});
