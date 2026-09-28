// Test-only observation INSIDE the real pinned server process. No fake handlers.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const [entry, workspace, receipt] = process.argv.slice(2);
const metadata = JSON.parse(fs.readFileSync(path.join(path.dirname(entry), '..', 'package.json')));
if (metadata.name !== '@modelcontextprotocol/server-filesystem' || metadata.version !== '2026.7.10') {
  throw new Error('S5 requires the exact reviewed filesystem package');
}
const record = (event) => {
  const fd = fs.openSync(receipt, 'a');
  try {
    fs.writeSync(fd, JSON.stringify({ pid: process.pid, ...event }) + '\n');
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
};
// Resolve the SDK belonging to this installed package, then its ESM implementation
// (the official entry point imports ESM). Fail closed if the layout changes.
const require = createRequire(pathToFileURL(entry));
const resolvedPath = require.resolve('@modelcontextprotocol/sdk/server/stdio.js');
const sdkPath = resolvedPath
  .replace(`${path.sep}dist${path.sep}cjs${path.sep}`, `${path.sep}dist${path.sep}esm${path.sep}`);
if (sdkPath === resolvedPath) throw new Error('unsupported SDK resolution layout');
const { StdioServerTransport } = await import(pathToFileURL(sdkPath).href);
const start = StdioServerTransport.prototype.start;
StdioServerTransport.prototype.start = async function () {
  const onmessage = this.onmessage;
  if (typeof onmessage !== 'function') throw new Error('missing real server dispatch');
  this.onmessage = (message, ...rest) => {
    record({ event: 'arrival', message });
    return onmessage(message, ...rest);
  };
  record({ event: 'hooked' });
  return start.call(this);
};
record({ event: 'boot', package: `${metadata.name}@${metadata.version}`, entry });
// EOF is an ordered drain barrier: all preceding stdio bytes have been parsed.
// Exit is a second barrier; neither is inferred from an empty receipt file.
process.stdin.once('end', () => record({ event: 'eof' }));
process.once('exit', (code) => record({ event: 'exit', code }));
process.argv = [process.execPath, entry, workspace];
await import(pathToFileURL(entry).href);
