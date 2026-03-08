#!/usr/bin/env node
/**
 * Generate Tauri app icons from assets/el-logo.webp.
 * Creates a square version (required by tauri icon) and runs tauri icon.
 * Single source of truth: assets/el-logo.webp
 */
import { createRequire } from "module";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { existsSync, unlinkSync } from "fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const rootDir = join(__dirname, "../..");
const logoPath = join(rootDir, "assets/el-logo.webp");
const squarePath = join(rootDir, "assets/logo-square-temp.png");

async function main() {
  if (!existsSync(logoPath)) {
    console.error("Error: assets/el-logo.webp not found");
    process.exit(1);
  }

  let sharp;
  try {
    const require = createRequire(import.meta.url);
    sharp = require("sharp");
  } catch {
    console.error("Error: sharp is required. Run: npm install --save-dev sharp");
    process.exit(1);
  }

  const img = await sharp(logoPath);
  const { width, height } = await img.metadata();
  const size = Math.max(width, height);

  await sharp({
    create: {
      width: size,
      height: size,
      channels: 4,
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    },
  })
    .composite([{ input: logoPath, left: Math.floor((size - width) / 2), top: Math.floor((size - height) / 2) }])
    .png()
    .toFile(squarePath);

  try {
    const { execSync } = await import("child_process");
    execSync(`npx tauri icon "${squarePath}"`, {
      cwd: join(rootDir, "gui"),
      stdio: "inherit",
    });
  } finally {
    if (existsSync(squarePath)) unlinkSync(squarePath);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
