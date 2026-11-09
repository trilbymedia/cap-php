#!/usr/bin/env node
// Offline maintainer tool: node tools/build-instrumentation-template.mjs /path/to/cap/core/src/instrumentation.js
// Input: capjs-core@0.1.11, upstream bc8166e93d0b2ea3a1548c4d416645c33d422b98 (Apache-2.0).
// The browser checks/collector stay upstream code; PHP supplies per-request arithmetic and binding keys.
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { resolve, dirname } from 'node:path';

const input = resolve(process.argv[2]);
let src = readFileSync(input, 'utf8');
function replace(before, after) {
  if (!src.includes(before)) throw new Error(`Upstream changed: ${before}`);
  src = src.replace(before, after);
}
replace('from "./detect.js"', `from ${JSON.stringify(pathToFileURL(resolve(dirname(input), 'detect.js')).href)}`);
replace('const blockChecks = blockAutomatedBrowsers\n    ? buildBlockChecks(rVar(), id, hF, hSet, h)\n    : "";', 'const blockChecks = "if(__CAP_BLOCK__){" + buildBlockChecks(rVar(), id, hF, hSet, h) + "}";');
replace('JSON.parse(${JSON.stringify(JSON.stringify(cfg))})', '__CAP_CONFIG__');
replace('observe:${observe}', 'observe:__CAP_OBSERVE__');
replace('${observe ? `${post(', '${observe ? `if(__CAP_OBSERVE__){${post(');
replace(';await ${finP};`', ';await ${finP};}`');
src += `\nexport function template() { return buildClientScript({
  id: '__CAP_ID__', vars: [0,1,2,3].map(i=>'__CAP_VAR_'+i+'__'),
  initVals: [0,1,2,3].map(i=>'__CAP_INIT_'+i+'__'), clientEqs: '__CAP_EQUATIONS__',
  blockAutomatedBrowsers: true, checkSeed: 1935826701,
  seedKeys: [[0,1],[2,3]].map(a=>a.map(i=>'__CAP_KEY_'+i+'__')),
  salts: [0,1,2,3].map(i=>'__CAP_SALT_'+i+'__'), fold: [0,1],
  cfg: {bh:1, ia:1, sens:SENSITIVE_FIELDS, marks:AGENT_MARKS, attrs:MARK_ATTRS}
}); }
export const config = {bh:0, ia:0, sens:SENSITIVE_FIELDS, marks:AGENT_MARKS, attrs:MARK_ATTRS};\n`;
const mod = await import('data:text/javascript;base64,' + Buffer.from(src).toString('base64'));
const output = new URL('../src/Instrumentation/', import.meta.url);
writeFileSync(new URL('client.js', output), '// Derived from capjs-core 0.1.11; Apache-2.0; see UPSTREAM.md.\n' + mod.template() + '\n');
writeFileSync(new URL('collector-config.json', output), JSON.stringify(mod.config) + '\n');
const { AGENT_ARTIFACTS } = await import(pathToFileURL(resolve(dirname(input), 'agents.js')).href);
writeFileSync(new URL('agent-artifacts.json', output), JSON.stringify(AGENT_ARTIFACTS) + '\n');
