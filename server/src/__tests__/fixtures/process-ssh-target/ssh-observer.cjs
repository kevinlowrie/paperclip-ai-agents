// Test transport observer; unsafe baseline commands never reach a real wire.
const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");
const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const args = process.argv.slice(3);
const chunks = [];
let size = 0;
process.stdin.on("data", chunk => {
  size += chunk.length;
  if (size > 2300000) { process.stderr.write("fixture observer input cap\n"); process.exit(91); }
  chunks.push(chunk);
});
process.stdin.on("end", () => {
  const body = Buffer.concat(chunks);
  const serializedArgs = JSON.stringify(args);
  const unsafeProfile = ["/etc/profile", "/.profile", "/.bash_profile", "/.bashrc", "/.zprofile"]
    .some(text => serializedArgs.includes(text));
  const privateArgv = config.canaries.some(text => serializedArgs.includes(text));
  const portIndex = args.indexOf("-p");
  const targetMatches = portIndex >= 0 && args[portIndex + 1] === String(config.port)
    && args[args.length - 2] === `${config.username}@127.0.0.1`;
  const wireReached = config.permitWire !== false && !unsafeProfile && !privateArgv && targetMatches;
  const captureDir = fs.mkdtempSync(path.join(config.captures, "call-"));
  fs.chmodSync(captureDir, 0o700);
  fs.writeFileSync(path.join(captureDir, "input.bin"), body, { mode: 0o600 });
  fs.writeFileSync(path.join(captureDir, "original.json"), JSON.stringify({ args,
    inputBytes: body.length, unsafeProfile, privateArgv, targetMatches, wireReached,
    ambientCanaryPresent: process.env.FIXTURE_AMBIENT_PROVIDER === "fixture-ambient-provider-canary" }), { mode: 0o600 });
  if (!wireReached) {
    process.stderr.write("fixture observer refused unsafe transport before wire\n");
    process.exitCode = 255;
    return;
  }
  // This independent guard protects the fixture. It cannot satisfy assertions
  // about the original helper args recorded above.
  const child = spawn("/usr/bin/ssh", ["-F", "/dev/null", "-o", "IdentityAgent=none",
    "-o", "IdentitiesOnly=yes", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
    "-o", "GlobalKnownHostsFile=/dev/null", ...args], { stdio: ["pipe", "pipe", "pipe"] });
  child.stdout.pipe(process.stdout);
  child.stderr.pipe(process.stderr);
  child.stdin.on("error", () => {});
  child.stdin.end(body);
  let killTimer;
  process.on("SIGTERM", () => {
    child.kill("SIGTERM");
    killTimer = setTimeout(() => child.kill("SIGKILL"), 200);
  });
  child.on("error", () => { process.stderr.write("fixture SSH launch failed\n"); process.exitCode = 93; });
  child.on("close", (code, signal) => {
    clearTimeout(killTimer);
    fs.writeFileSync(path.join(captureDir, "closed.json"), JSON.stringify({ code, signal }), { mode: 0o600 });
    process.exitCode = code ?? 94;
  });
});
