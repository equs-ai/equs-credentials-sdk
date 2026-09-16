import { IncomingMessage, ServerResponse } from "http";
import { ViteDevServer } from "vite";
import path from "path";
import fs from "fs";

const ROOT_PATH = path.resolve(__dirname, "../..");

export default function wasmPlugin() {
  return {
    name: "wasm-plugin",
    configureServer(server: ViteDevServer) {
      server.middlewares.use((req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => {
        if (req.url?.endsWith(".wasm")) {
          const wasmPath = path.join(ROOT_PATH, "node_modules/@equs-ai/equs-credentials-sdk", path.basename(req.url));
          const wasmFile = fs.readFileSync(wasmPath);
          res.setHeader("Content-Type", "application/wasm");
          res.end(wasmFile);
          return;
        }
        next();
      });
    },
  };
}
