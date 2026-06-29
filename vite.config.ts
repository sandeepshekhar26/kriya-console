/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri wraps this same Vite frontend (D-018): the dev server runs on a fixed port the Tauri
// window points at, and Vite must not clear the screen (it would hide the Rust/cargo output the
// Tauri CLI interleaves). `TAURI_DEV_HOST` is injected by the Tauri CLI during `tauri dev`.
const host = process.env.TAURI_DEV_HOST;

export default defineConfig({
  plugins: [react()],
  // Build-time demo flag. The shipped desktop app is built with KRIYA_DEMO unset → `false`, so the
  // sample/demo seed (and its fixtures) are dead-code-eliminated from the bundle. The web walkthrough
  // is built with `KRIYA_DEMO=1 vite build` → `true`. Never seed sample data into the shipped product.
  define: { __KRIYA_DEMO__: JSON.stringify(process.env.KRIYA_DEMO === "1") },
  // Prevent Vite from obscuring Rust compiler errors during `tauri dev`.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    // Don't reload the frontend when the Rust source changes — the Tauri CLI rebuilds that.
    watch: { ignored: ["**/src-tauri/**"] },
  },
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
  },
});
