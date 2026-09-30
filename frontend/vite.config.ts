import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: { port: 5173 },
  build: {
    rollupOptions: {
      output: {
        // REQ-CONSOLE-015: the graph libraries load only with the graph (lazy
        // SurfaceGraph). Two chunks keep each well below the 500 kB warning.
        manualChunks: { "graph-core": ["cytoscape"], "graph-layout": ["cytoscape-dagre"] },
      },
    },
  },
});
