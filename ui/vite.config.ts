import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// `npm run dev` serves the UI with hot reloading, and passes API requests on
// to a running node's peer endpoint: CAIRN_URL, or the default one.
const node = process.env.CAIRN_URL ?? "http://127.0.0.1:9431";

export default defineConfig({
  plugins: [solid()],
  server: {
    proxy: { "/api": { target: node, changeOrigin: true } },
  },
  build: {
    target: "es2022",
    // The CSP forbids inline scripts and styles, so nothing may be inlined.
    assetsInlineLimit: 0,
  },
});
