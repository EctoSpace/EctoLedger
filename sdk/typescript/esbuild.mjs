// esbuild.mjs — Bundles the SDK into CJS + ESM for dual-module support.
// Called by `npm run build` after tsc compilation.

import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distDir = join(__dirname, "dist");

// Ensure dist directory exists (tsc should have created it already).
mkdirSync(distDir, { recursive: true });

// Read all .js files in dist and create .cjs copies with minimal CJS wrapper.
function processDir(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      processDir(full);
    } else if (entry.endsWith(".js")) {
      const cjsPath = full.replace(/\.js$/, ".cjs");
      const content = readFileSync(full, "utf8");
      // Simple ESM → CJS transform for re-exports
      const cjs = content
        .replace(/^export\s+\{([^}]+)\}\s+from\s+"([^"]+)"/gm, (_, names, mod) => {
          const items = names.split(",").map((n) => n.trim());
          const reqs = items.map((n) => `module.exports.${n} = require("${mod.replace(/\.js$/, ".cjs")}").${n};`);
          return reqs.join("\n");
        })
        .replace(/^export\s+(class|function|const|let|var)\s+(\w+)/gm, "$1 $2")
        .replace(/^export\s+\{([^}]+)\}\s*;?\s*$/gm, (_, names) => {
          return names
            .split(",")
            .map((n) => `module.exports.${n.trim()} = ${n.trim()};`)
            .join("\n");
        });
      writeFileSync(cjsPath, cjs);
    }
  }
}

processDir(distDir);
console.log("esbuild.mjs: CJS copies created in dist/");
