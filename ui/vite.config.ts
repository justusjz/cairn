import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// The console's UI, served from the root of the console's origin
// (`--listen-console`). `npm run dev` serves it with hot reloading, and
// passes API requests on to a running node's console: CAIRN_CONSOLE, or the
// default one. (Passkeys are bound to the console URL's host, so sign in
// through the node's own port when trying it against `localhost`.)
const node = process.env.CAIRN_CONSOLE ?? "http://localhost:9480";

export default defineConfig({
  base: "/",
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
