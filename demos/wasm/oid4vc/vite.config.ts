import { defineConfig, searchForWorkspaceRoot } from "vite";
import react from "@vitejs/plugin-react";
import process from "process";

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  assetsInclude: ["**/*.wasm"],
  server: {
    middlewareMode: false,
    port: 3000,
    fs: {
      allow: [searchForWorkspaceRoot(process.cwd()), "../../../wrappers/wasm/pkg"],
    },
  },
});
