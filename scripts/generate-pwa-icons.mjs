#!/usr/bin/env node
import sharp from 'sharp';
import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import toIco from 'to-ico';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, '..');
const publicDir = join(root, 'public');
const iconsDir = join(publicDir, 'icons');
const logoPath = join(publicDir, 'logo.png');

if (!existsSync(logoPath)) {
  console.error('logo.png not found in public/');
  process.exit(1);
}

if (!existsSync(iconsDir)) {
  mkdirSync(iconsDir, { recursive: true });
}

await sharp(logoPath).resize(32, 32).png().toFile(join(publicDir, 'favicon-32.png'));
await sharp(logoPath).resize(180, 180).png().toFile(join(iconsDir, 'icon-180.png'));
await sharp(logoPath).resize(192, 192).png().toFile(join(iconsDir, 'icon-192.png'));
await sharp(logoPath).resize(512, 512).png().toFile(join(iconsDir, 'icon-512.png'));

// favicon.ico per tab browser (Chrome richiede /favicon.ico)
const png16 = await sharp(logoPath).resize(16, 16).png().toBuffer();
const png32 = await sharp(logoPath).resize(32, 32).png().toBuffer();
const ico = await toIco([png16, png32]);
writeFileSync(join(publicDir, 'favicon.ico'), ico);

console.log('Icons generated: favicon.ico, favicon-32.png, icons/icon-180.png, icon-192.png, icon-512.png');
