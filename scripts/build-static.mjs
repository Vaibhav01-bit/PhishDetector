import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "dist");

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
await cp(path.join(root, "static"), path.join(dist, "static"), { recursive: true });

await renderTemplate("index.html", "index.html");
await renderTemplate("usecases.html", "usecases/index.html");

async function renderTemplate(templateName, outputName) {
  const source = await readFile(path.join(root, "templates", templateName), "utf8");
  const html = stripJinja(rewriteUrlFor(source));
  const outputPath = path.join(dist, outputName);
  await mkdir(path.dirname(outputPath), { recursive: true });
  await writeFile(outputPath, html, "utf8");
}

function rewriteUrlFor(source) {
  return source
    .replace(/\{\{\s*url_for\('home'\)\s*\}\}/g, "/")
    .replace(/\{\{\s*url_for\('usecases'\)\s*\}\}/g, "/usecases/")
    .replace(/\{\{\s*url_for\('predict'\)\s*\}\}/g, "/result")
    .replace(/\{\{\s*url_for\('rescan_url'\)\s*\}\}/g, "/rescan")
    .replace(
      /\{\{\s*url_for\('static',\s*filename='([^']+)'\)\s*\}\}/g,
      (_match, filename) => `/static/${filename}`,
    )
    .replace(/\{\{\s*url_for\('sandbox_results'[\s\S]*?\)\s*\}\}/g, "#");
}

function stripJinja(source) {
  const pieces = source.split(/({%[\s\S]*?%})/g);
  const stack = [{ active: true, matched: true, parentActive: true }];
  let output = "";

  for (const piece of pieces) {
    if (!piece.startsWith("{%")) {
      if (isActive(stack)) {
        output += piece;
      }
      continue;
    }

    const tag = piece.slice(2, -2).trim();
    const [kind] = tag.split(/\s+/, 1);
    const frame = stack[stack.length - 1];

    if (kind === "if") {
      const parentActive = isActive(stack);
      const matched = evaluateCondition(tag.slice(2).trim());
      stack.push({ parentActive, active: parentActive && matched, matched });
    } else if (kind === "elif") {
      const matched = evaluateCondition(tag.slice(4).trim());
      frame.active = frame.parentActive && !frame.matched && matched;
      frame.matched = frame.matched || matched;
    } else if (kind === "else") {
      frame.active = frame.parentActive && !frame.matched;
      frame.matched = true;
    } else if (kind === "endif") {
      stack.pop();
    } else if (kind === "for") {
      stack.push({ parentActive: isActive(stack), active: false, matched: false });
    } else if (kind === "endfor") {
      stack.pop();
    }
  }

  return output.replace(/\{\{[\s\S]*?\}\}/g, "");
}

function isActive(stack) {
  return stack.every((frame) => frame.active);
}

function evaluateCondition(expression) {
  const normalized = expression.replace(/\s+/g, " ").trim();
  if (normalized === "not name" || normalized === "not email_results") {
    return true;
  }
  return false;
}
