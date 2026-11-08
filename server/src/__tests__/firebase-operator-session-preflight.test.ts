import http from "node:http";
import net from "node:net";
import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { firebaseOperatorPreAuthRequestHandler } from "../auth/firebase-operator-session-preflight.js";

const PUBLIC = "https://paperclip.example.test";
const LAB = "https://paperclip.lab.example.test";
const PATH = "/api/auth/firebase-session/begin";
const EXCHANGE = "/api/auth/firebase-session/exchange";
const JSON_TYPE = "application/json";

function appFor(options: { maxBodyBytes?: number; origins?: string[] } = {}) {
  const app = express();
  app.use(firebaseOperatorPreAuthRequestHandler({
    trustedOrigins: new Set(options.origins ?? [PUBLIC, LAB]),
    ...(options.maxBodyBytes ? { maxBodyBytes: options.maxBodyBytes } : {}),
  }));
  app.post([PATH, EXCHANGE], (req, res) => {
    res.status(200).json({ method: req.method, path: req.path, body: req.body ?? null });
  });
  app.all("/api/auth/*splat", (_req, res) => res.status(418).json({ ordinaryAuth: true }));
  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(413).json({ error: "body rejected" });
  });
  return app;
}

describe("Firebase operator pre-auth HTTP boundary", () => {
  const servers: http.Server[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))));
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
    const chunked = await new Promise<{ status: number; headers: http.IncomingHttpHeaders }>((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port, method: "POST", path: PATH, headers: { Host: new URL(PUBLIC).host, Origin: PUBLIC, "Content-Type": JSON_TYPE, "Transfer-Encoding": "chunked" } }, (res) => {
        res.resume(); res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers }));
      });
      req.on("error", reject);
      req.write(oversizedBody.slice(0, 2000));
      req.write(oversizedBody.slice(2000, 4000));
      req.end(oversizedBody.slice(4000));
    });
    expect(chunked.status).toBe(413);
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
});
