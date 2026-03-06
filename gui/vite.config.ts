import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";
import tailwindcss from "@tailwindcss/vite";
import { readFileSync } from "fs";

const pkg = JSON.parse(readFileSync("package.json", "utf-8"));

// https://vitejs.dev/config/
export default defineConfig(() => ({
  plugins: [tailwindcss(), svelte()],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },
  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    // Proxy /api and /metrics to the backend so requests that accidentally
    // reach the Vite dev server get forwarded instead of returning an HTML 404.
    proxy: {
      '/api': {
        target: process.env.ECTO_HOST || 'http://127.0.0.1:3000',
        changeOrigin: true,
      },
      '/metrics': {
        target: process.env.ECTO_HOST || 'http://127.0.0.1:3000',
        changeOrigin: true,
      },
    },
    watch: {
      // 3. tell vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
  // 4. Explicitly set the build output directory so tauri.conf.json frontendDist
  //    ("../dist") always points to the correct location regardless of Vite version
  //    defaults.  Without this, Vite could resolve to a different directory and the
  //    Tauri production bundle would fail to find the frontend assets.
  build: {
    outDir: "dist",
    // Tauri uses WebKit on macOS; target ensures compatible output
    target: process.env.TAURI_ENV_PLATFORM === "windows" ? "chrome105" : "safari13",
    minify: !process.env.TAURI_ENV_DEBUG ? ("esbuild" as const) : false,
    sourcemap: !!process.env.TAURI_ENV_DEBUG,
  },
}));
