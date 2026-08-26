import { readFileSync, writeFileSync } from "node:fs";
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  // No source map: `noExternal` below inlines the PRIVATE @paybridge/mcp-core
  // into the bundle, and a map would ship that package's full sourcesContent
  // (internal paths, architecture notes, internal endpoints) to npm.
  sourcemap: false,
  // Bundle the internal workspace package — it's not published separately.
  noExternal: ["@paybridge/mcp-core"],
  // bin is invoked by node directly via the shebang in dist/index.js.
  banner: { js: "#!/usr/bin/env node" },
  // esbuild labels each bundled module with a `// <path>` banner. For the
  // inlined private package that publishes its internal file layout, so blank
  // those lines out (kept as `//` so offsets do not shift).
  onSuccess: async () => {
    const out = "dist/index.js";
    const src = readFileSync(out, "utf8");
    writeFileSync(out, src.replace(/^\/\/ \.\.\/mcp-core\/src\/.*$/gm, "//"));
  },
});
