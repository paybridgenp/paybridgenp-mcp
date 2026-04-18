import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  clean: true,
  sourcemap: true,
  // Bundle the internal workspace package — it's not published separately.
  noExternal: ["@paybridge/mcp-core"],
  // bin is invoked by node directly via the shebang in dist/index.js.
  banner: { js: "#!/usr/bin/env node" },
});
