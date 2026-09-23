# The Regulation Cell · project site

A static website for the Regulation Cell project: a home page with a how-to guide and an interactive control-loop demo, the 10-minute brief, the full white paper (plus a PDF copy), and the two research reports it was built from. Nothing needs to be built or installed, so it runs as-is on GitHub Pages.

Every page's content is **encrypted** with AES-256-GCM. The access phrase is the key: the browser stretches it with PBKDF2-SHA256 (310,000 rounds) and decrypts locally. Without the phrase, the repo contains only ciphertext, so it's safe to keep public. For extra safety, make the repo private (GitHub Pages on a private repo needs a paid plan).

```
index.html                 Home: access gate, how to use, loop demo, links
brief/index.html           The brief (sealed)
white-paper/index.html     The white paper (sealed)
report-a/index.html        Report A: The AI Watch Lab (sealed)
report-b/index.html        Report B: Closed-Loop Regulation (sealed)
assets/gate.js             Decryption and gate logic (public, no secrets)
assets/white-paper.pdf.enc PDF of the white paper (sealed)
assets/favicon.svg
tools/seal.mjs             Change the access phrase (Node 18+, no dependencies)
```

## Put it online (GitHub Pages)

**Option A: upload in the browser (your usual flow)**
1. Create a new repository on GitHub, for example `regulation-cell`.
2. Click **Add file → Upload files** and drag in *everything in this folder*, subfolders included (`assets`, `brief`, `white-paper`, `report-a`, `report-b`, `tools`). GitHub keeps the folder structure.
3. Commit.
4. Go to **Settings → Pages**. Under *Build and deployment*, set Source to **Deploy from a branch**, Branch to **main**, folder **/ (root)**, then **Save**.
5. After about a minute the site is live at `https://<your-username>.github.io/regulation-cell/`.

**Option B: git (faster for updates)**
This folder is already a git repo with one commit.
```
git remote add origin https://github.com/<your-username>/regulation-cell.git
git push -u origin main
```
Then do step 4 above. After that, every update is `git add -A && git commit -m "update" && git push`, instead of re-uploading files. GitHub Desktop does the same with buttons.

**Custom domain (optional).** In Settings → Pages, add a domain such as `cell.yourdomain.com`, then create a CNAME DNS record pointing to `<your-username>.github.io`. Keep **Enforce HTTPS** on, because the browser's crypto only works over HTTPS.

## The access phrase

- The phrase is **case-insensitive**, and spaces at the start and end are ignored.
- Send the link and the phrase through different channels.
- "Remember on this device" keeps a device unlocked until someone presses **Lock** on the home page.

**To change the phrase** (needs Node 18+ on your computer):
```
node tools/seal.mjs rephrase --old "current phrase" --new "new phrase"
```
This re-encrypts every page and the PDF in place. Commit and push (or re-upload) the changed files: every `index.html`, plus `assets/white-paper.pdf.enc`.

A longer phrase is stronger. Four or more unrelated words is good; a single short word is not.

## What this protection is, and isn't

- It stops anyone without the phrase from reading the content, even if they download the repo.
- It isn't user accounts. Anyone you give the phrase to can read everything and share it on.
- Changing the phrase locks out new visits, but not copies someone already saved.
- Plaintext sources are **not** in this repo, and shouldn't be. Keep them out of any public repo.

## Updating the content

The brief and white paper are generated documents. To publish a revised version, seal the new plaintext with `node tools/seal.mjs build --phrase "..." --src <folder with home.html, brief.html, white-paper.html, white-paper.pdf>`, then commit.

v1 · 2026-09-23
