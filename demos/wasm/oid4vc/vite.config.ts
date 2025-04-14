import { defineConfig, searchForWorkspaceRoot } from "vite";
import react from "@vitejs/plugin-react";
import process from "process";
import wasmPlugin from "./src/components/wasmPlugin.ts";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), wasmPlugin()],
  assetsInclude: ["**/*.wasm"],
  server: {
    middlewareMode: false,
    port: 3000,
    fs: {
      allow: [searchForWorkspaceRoot(process.cwd()), "../../../wrappers/wasm/pkg"],
    },
  },
});
