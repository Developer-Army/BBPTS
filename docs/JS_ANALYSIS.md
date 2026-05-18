# JS Analysis Engine

BBPTS uses [Goja](https://github.com/dop251/goja) — a pure-Go ECMAScript 5.1+ engine — for JavaScript analysis during recon.

## Why Goja instead of regex-based scanning?

Regex-based JS scanning fails on:
- Minified/obfuscated code where variable names are single characters
- Dynamically constructed strings (`baseURL + "/api/" + endpoint`)
- Prototype chain traversal to find inherited properties
- Detecting eval-based dynamic endpoint registration

Goja executes the JS in a sandboxed interpreter, allowing BBPTS to:
1. Resolve computed string concatenations into final endpoint strings
2. Walk object prototype chains to extract inherited API paths
3. Detect dynamic `fetch()`/`XMLHttpRequest` calls with runtime-resolved URLs
4. Extract secrets embedded in closures

## Performance Trade-offs

Goja adds ~20MB to the binary and ~150ms startup overhead per JS file executed.

Mitigations in place:
- JS analysis runs only on Stage 4 (Fuzz + JS Analysis), not earlier stages
- Each Goja runtime is created fresh per file and GC'd immediately after
- A `context.WithTimeout` of 10s per file prevents infinite loops in hostile JS
- Files larger than 5MB are skipped and logged as `js_analysis: skipped (too large)`

## Sandboxing

The Goja runtime has no access to the host filesystem, network, or OS. It only runs
the JS content retrieved during crawling. Sensitive APIs (`require`, `process`, `fs`)
are not exposed to the runtime.
