const fs = require("node:fs");
const expected = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const paths = ["/home", "/srv/home", "/etc/profile", "/etc/bash.bashrc"];
const inaccessible = paths.every(name => { try { fs.accessSync(name); return false; } catch { return true; } });
const homeUnchanged = process.env.HOME === expected.home;
const codexHomeUnchanged = process.env.CODEX_HOME === expected.codexHome;
const result = { inaccessible, homeUnchanged, codexHomeUnchanged, checkedPaths: paths };
process.stdout.write(JSON.stringify(result));
if (!inaccessible || !homeUnchanged || !codexHomeUnchanged) process.exitCode = 96;
