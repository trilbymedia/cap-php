# Browser instrumentation provenance

`client.js` and `collector-config.json` derive from `core/src/instrumentation.js` in [Cap at bc8166e93d0b2ea3a1548c4d416645c33d422b98](https://github.com/tiagozip/cap/blob/bc8166e93d0b2ea3a1548c4d416645c33d422b98/core/src/instrumentation.js), released as capjs-core 0.1.11. Copyright Tiago; licensed under Apache-2.0 (see the repository LICENSE).

The offline maintainer tool `tools/build-instrumentation-template.mjs` extracts upstream's native checks, environment checks, automation checks, browser probes and interaction/behavior collector into a parameterized browser program. PHP fills in a new ID, variable names, arithmetic/DOM program, binding keys and policy for every challenge. There is no Node dependency at runtime. The generated template deliberately keeps upstream's fixed check hashing seed; it does not run esbuild or javascript-obfuscator. The binding seed and answer values change on every request. Regenerating the template changes internal names/order randomly, so byte-for-byte reproducibility is not expected.

The server verification, browser detection and behavior rules are PHP translations of the same release's `instrumentation.js`, `detect.js` and `behavior.js`. Tests include upstream-generated vectors. Keeping these rules and the browser program from the same upstream release matters: never update one independently.
