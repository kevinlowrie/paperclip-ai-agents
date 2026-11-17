// Synthetic process only: bounded modes, no network/provider/auth behavior.
const fs = require("node:fs");
const [mode, outputPath, ...args] = process.argv.slice(2);
if (mode === "sentinel") {
  fs.writeFileSync(outputPath, "configured command ran\n", { mode: 0o600 });
  process.stdout.write("fixture-command-completed\n");
} else if (mode === "inspect") {
  process.stdout.write(JSON.stringify({ cwd: process.cwd(), args,
    env: Object.fromEntries(["FIXTURE_VALUE", "PAPERCLIP_API_KEY", "PAPERCLIP_RUN_ID",
      "PAPERCLIP_RUNTIME_TOOLS_TOKEN"].map(key => [key, process.env[key] ?? null])) }));
} else if (mode === "nonzero") {
  process.stdout.write("fixture-stdout\n");
  process.stderr.write("fixture-stderr\n");
  process.exitCode = 23;
} else if (mode === "pause") {
  setTimeout(() => process.stdout.write("late\n"), 2000);
} else if (mode === "remote-bounded") {
  const [durationText, exitText] = args;
  const ttl = Number(durationText);
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > 5000) throw new Error("bad fixture TTL");
  process.on("SIGHUP", () => {});
  process.on("SIGTERM", () => {});
  const marker = { pid: process.pid, startedAt: Date.now(), mode };
  fs.writeFileSync(outputPath + ".started", JSON.stringify(marker), { mode: 0o600 });
  const tick = setInterval(() => fs.writeFileSync(outputPath + ".tick", String(Date.now())), 50);
  setTimeout(() => {
    clearInterval(tick);
    fs.writeFileSync(outputPath + ".done", JSON.stringify({ ...marker, finishedAt: Date.now() }), { mode: 0o600 });
    process.exit(Number(exitText || 0));
  }, ttl);
} else if (mode === "exit") {
  process.stdout.write("remote-stdout\n");
  process.stderr.write("remote-stderr\n");
  process.exitCode = Number(args[0] || 0);
} else {
  throw new Error("unknown fixture mode");
}
