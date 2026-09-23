#!/usr/bin/env node
// Seal (encrypt) the site's pages with an access phrase, or change the phrase.
// Zero dependencies: Node 18+ built-in crypto only.
//
//   node tools/seal.mjs rephrase --old "current phrase" --new "new phrase"
//       Re-encrypts every sealed page and file in this repo under a new phrase.
//
//   node tools/seal.mjs build --phrase "phrase" --src <plaintext dir>
//       Seals plaintext sources into the site (maintainer use; keep sources out of git).
//
// Format matches assets/gate.js: base64( 0x01 | salt16 | iv12 | ciphertext | tag16 ),
// key = PBKDF2-SHA256(phrase normalized: NFKC, trimmed, lowercase; 310,000 rounds).

import { pbkdf2Sync, randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const ITER = 310000;
const TARGETS = [
  { src: 'home.html', out: 'index.html', kind: 'inline' },
  { src: 'brief.html', out: 'brief/index.html', kind: 'inline' },
  { src: 'white-paper.html', out: 'white-paper/index.html', kind: 'inline' },
  { src: 'report-a.html', out: 'report-a/index.html', kind: 'inline' },
  { src: 'report-b.html', out: 'report-b/index.html', kind: 'inline' },
  { src: 'white-paper.pdf', out: 'assets/white-paper.pdf.enc', kind: 'binary' },
];
const BLOCK = /(<script type="application\/octet-stream" id="sealed">)([\s\S]*?)(<\/script>)/;

const norm = (p) => String(p).normalize('NFKC').trim().toLowerCase();
const deriveKey = (phrase, salt) => pbkdf2Sync(norm(phrase), salt, ITER, 32, 'sha256');

function seal(plain, key, salt) {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([Buffer.from([1]), salt, iv, ct, c.getAuthTag()]);
}
function open(buf, phrase) {
  if (buf[0] !== 1) throw new Error('unknown payload format');
  const salt = buf.subarray(1, 17), iv = buf.subarray(17, 29);
  const body = buf.subarray(29, buf.length - 16), tag = buf.subarray(buf.length - 16);
  const d = createDecipheriv('aes-256-gcm', deriveKey(phrase, salt), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(body), d.final()]);
}

function args() {
  const a = process.argv.slice(2), o = { cmd: a[0] };
  for (let i = 1; i < a.length; i += 2) o[a[i].replace(/^--/, '')] = a[i + 1];
  return o;
}

function writeSealed(t, sealed) {
  const path = join(ROOT, t.out);
  if (t.kind === 'binary') { writeFileSync(path, sealed); return; }
  const html = readFileSync(path, 'utf8');
  if (!BLOCK.test(html)) throw new Error(`no sealed block in ${t.out}`);
  writeFileSync(path, html.replace(BLOCK, (_, a, _b, c) => a + sealed.toString('base64') + c));
}
function readSealed(t) {
  const path = join(ROOT, t.out);
  if (!existsSync(path)) return null;
  if (t.kind === 'binary') return readFileSync(path);
  const m = readFileSync(path, 'utf8').match(BLOCK);
  return m && m[2].trim() ? Buffer.from(m[2].trim(), 'base64') : null;
}

const o = args();
try {
if (o.cmd === 'build') {
  if (!o.phrase || !o.src) throw new Error('usage: build --phrase "..." --src <dir>');
  const salt = randomBytes(16), key = deriveKey(o.phrase, salt);
  for (const t of TARGETS) {
    const p = join(o.src, t.src);
    if (!existsSync(p)) { console.log(`skip ${t.src} (not found)`); continue; }
    writeSealed(t, seal(readFileSync(p), key, salt));
    console.log(`sealed ${t.src} -> ${t.out}`);
  }
} else if (o.cmd === 'rephrase') {
  if (!o.old || !o.new) throw new Error('usage: rephrase --old "..." --new "..."');
  const plain = [];
  for (const t of TARGETS) {
    const buf = readSealed(t);
    if (!buf) continue;
    try { plain.push([t, open(buf, o.old)]); }
    catch { throw new Error(`the old phrase does not open ${t.out}; nothing was changed`); }
  }
  const salt = randomBytes(16), key = deriveKey(o.new, salt);
  for (const [t, p] of plain) { writeSealed(t, seal(p, key, salt)); console.log(`resealed ${t.out}`); }
  console.log('Done. Commit and push; anyone with the old phrase saved on a device must enter the new one.');
} else {
  console.log('usage:\n  node tools/seal.mjs rephrase --old "current" --new "new"\n  node tools/seal.mjs build --phrase "..." --src <dir>');
}
} catch (e) {
  console.error('Error: ' + e.message);
  process.exit(1);
}
