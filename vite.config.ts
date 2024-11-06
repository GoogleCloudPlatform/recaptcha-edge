/**
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// vite.config.ts
import { defineConfig } from "vite"; // Import Vite's configuration helper

export default defineConfig({
  // Project root directory (where index.html is located)
  root: "./",

  // Base public path for build output (optional, defaults to '/')
  base: "/",

  // Build options
  build: {
    // Output directory for production build
    outDir: "./dist",
  },

  // Resolve options
  resolve: {
    alias: {
      // Example alias for easier imports
      "@/": `${__dirname}/src/`,
    },
  },

  // Test-specific options
  test: {
    // Test environment (e.g., 'jsdom', 'node', 'happy-dom')
    environment: "node",

    // Include files for testing (glob patterns)
    include: ["src/**/*.test.{ts,tsx}"],

    // Exclude files from testing (glob patterns)
    exclude: ["node_modules"],

    // Enable coverage report generation
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
    },
  },
});
