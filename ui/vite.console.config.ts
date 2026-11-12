import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// The console (`console.html`): a page of its own, served from the root of
// the console's origin (`--listen-console`), built after the dashboard into
// dist/console/, which the node embeds with the rest. `npm run dev:console`
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
    outDir: "dist/console",
    emptyOutDir: false,
    // The CSP forbids inline scripts and styles, so nothing may be inlined.
    assetsInlineLimit: 0,
    rollupOptions: { input: "console.html" },
  },
});
