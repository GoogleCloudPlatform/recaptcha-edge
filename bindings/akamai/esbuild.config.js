import * as esbuild from "esbuild";

await esbuild.build({
  entryPoints: ["src/edge_worker.ts"],
  bundle: true,
  outdir: "dist",
  external: ["create-response", "http-request", "html-rewriter", "streams", "log"],
  platform: "node",
  format: "esm",
});
