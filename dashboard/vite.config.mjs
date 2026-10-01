import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: `${(process.env.PUBLIC_URL || "/dashboard").replace(/\/+$/, "")}/`,
  build: {
    outDir: "build",
    sourcemap: false,
    target: ["chrome87", "edge88", "firefox78", "safari14"],
  },
});
