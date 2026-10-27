// Builds the popup into ../chrome/popup  (no Vite needed: esbuild bundles the React code, Tailwind v4 compiles the CSS).
//   npm install && npm run build
import { build } from "esbuild";
import { compile } from "tailwindcss";
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const out = path.resolve(root, "../chrome/popup");
const require = createRequire(import.meta.url);

fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });

// 1) JS
await build({
  entryPoints: [path.join(root, "src/main.tsx")],
  outfile: path.join(out, "main.js"),
  bundle: true,
  minify: true,
  format: "iife",
  target: "chrome110",
  jsx: "automatic",
  define: { "process.env.NODE_ENV": '"production"' },
  legalComments: "none",
  logLevel: "warning",
});

// 2) CSS: Tailwind needs the list of class names used in the source; every token in src/ is offered, unknown ones are ignored.
function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)],
  );
}
const candidates = new Set();
for (const f of walk(path.join(root, "src")).filter((f) => /\.(tsx?|css)$/.test(f))) {
  for (const t of fs.readFileSync(f, "utf8").split(/[\s"'`{}<>;]+/)) if (t) candidates.add(t);
}
const compiler = await compile(fs.readFileSync(path.join(root, "src/index.css"), "utf8"), {
  base: root,
  loadStylesheet: async (id, base) => {
    const file = id.startsWith(".") ? path.resolve(base, id) : require.resolve(id === "tailwindcss" ? "tailwindcss/index.css" : id);
    return { path: file, base: path.dirname(file), content: fs.readFileSync(file, "utf8") };
  },
});
fs.writeFileSync(path.join(out, "main.css"), compiler.build([...candidates]));

// 3) HTML shell
fs.writeFileSync(
  path.join(out, "index.html"),
  `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SafeBrowse</title>
<link rel="stylesheet" href="main.css">
</head>
<body>
<div id="root"></div>
<script src="main.js"></script>
</body>
</html>
`,
);
console.log("popup built ->", out);
