// Print the extension as ONE script you can paste into the DevTools console of
// a github.com tab. For machines where Chrome blocks unpacked extensions.
//
//   node extension/tools/console-bundle.mjs | pbcopy      # macOS
//
// It runs exactly the content scripts from manifest.json, in order, plus the
// stylesheet. The only differences from the installed extension: nothing
// persists (no chrome.storage, so no cache, token or extra CAs), and it lasts
// until the tab is reloaded.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const ext = join(dirname(fileURLToPath(import.meta.url)), "..");
const cs = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8")).content_scripts[0];
const read = (p) => readFileSync(join(ext, p), "utf8");

const css = cs.css.map(read).join("\n");
const out = [
  `/* beamsig console bundle */`,
  `if (!document.getElementById("beamsig-style")) {`,
  `  const s = document.createElement("style"); s.id = "beamsig-style";`,
  `  s.textContent = ${JSON.stringify(css)}; document.head.appendChild(s);`,
  `}`,
  ...cs.js.map((p) => `;(function(){\n${read(p)}\n})();`),
].join("\n");
process.stdout.write(out + "\n");
