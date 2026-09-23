/* Regulation Cell access gate.
 * Pages ship AES-256-GCM ciphertext. The access phrase is stretched with
 * PBKDF2-SHA256 (310,000 rounds) into the key; nothing is sent over the network.
 * Payload layout (base64): version(1) | salt(16) | iv(12) | ciphertext+tag
 */
(function () {
  'use strict';
  var ITER = 310000;
  var KEYNAME = 'rc-access-key';
  var enc = new TextEncoder();
  var memKey = null;

  function b64d(s) {
    var bin = atob(String(s).replace(/\s+/g, ''));
    var u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  function b64e(u) {
    var s = '';
    for (var i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function parse(buf) {
    if (!buf || buf[0] !== 1) throw new Error('Unknown payload format');
    return { salt: buf.slice(1, 17), iv: buf.slice(17, 29), ct: buf.slice(29) };
  }
  function norm(phrase) { return String(phrase).normalize('NFKC').trim().toLowerCase(); }

  function derive(phrase, salt) {
    return crypto.subtle.importKey('raw', enc.encode(norm(phrase)), 'PBKDF2', false, ['deriveBits'])
      .then(function (base) {
        return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: ITER }, base, 256);
      })
      .then(function (bits) { return new Uint8Array(bits); });
  }
  function decryptWith(keyBytes, p) {
    return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt'])
      .then(function (k) { return crypto.subtle.decrypt({ name: 'AES-GCM', iv: p.iv }, k, p.ct); })
      .then(function (pt) { return new Uint8Array(pt); });
  }

  function cached(saltB64) {
    if (memKey && memKey.salt === saltB64) return b64d(memKey.key);
    var stores = [];
    try { stores.push(window.sessionStorage); } catch (e) {}
    try { stores.push(window.localStorage); } catch (e) {}
    for (var i = 0; i < stores.length; i++) {
      try {
        var v = JSON.parse(stores[i].getItem(KEYNAME) || 'null');
        if (v && v.salt === saltB64) return b64d(v.key);
      } catch (e) {}
    }
    return null;
  }
  function remember(saltB64, key, persist) {
    memKey = { salt: saltB64, key: b64e(key) };
    var v = JSON.stringify(memKey);
    try { window.sessionStorage.setItem(KEYNAME, v); } catch (e) {}
    if (persist) { try { window.localStorage.setItem(KEYNAME, v); } catch (e) {} }
  }
  function lock() {
    memKey = null;
    try { window.sessionStorage.removeItem(KEYNAME); } catch (e) {}
    try { window.localStorage.removeItem(KEYNAME); } catch (e) {}
  }

  /* Decrypt a payload with the cached key only (no prompt). Resolves null if locked. */
  function tryCached(buf) {
    var p = parse(buf);
    var key = cached(b64e(p.salt));
    if (!key) return Promise.resolve(null);
    return decryptWith(key, p).catch(function () { return null; });
  }
  function unlock(buf, phrase, persist) {
    var p = parse(buf);
    return derive(phrase, p.salt).then(function (key) {
      return decryptWith(key, p).then(function (plain) {
        remember(b64e(p.salt), key, persist);
        return plain;
      });
    });
  }

  /* Wire a form to a payload. opts: {payload, form, input, persist, status, onOpen} */
  function mount(opts) {
    var buf = b64d(opts.payload);
    function setStatus(msg, kind) {
      if (!opts.status) return;
      opts.status.textContent = msg;
      opts.status.setAttribute('data-kind', kind || '');
    }
    return tryCached(buf).then(function (plain) {
      if (plain) { opts.onOpen(plain, true); return; }
      if (opts.form) opts.form.hidden = false;
      if (opts.input) { try { opts.input.focus({ preventScroll: true }); } catch (e) {} }
      opts.form.addEventListener('submit', function (ev) {
        ev.preventDefault();
        var phrase = opts.input.value;
        if (!norm(phrase)) { setStatus('Enter the access phrase.', 'err'); return; }
        var btn = opts.form.querySelector('button[type="submit"]');
        if (btn) btn.disabled = true;
        setStatus('Deriving key…', 'busy');
        opts.form.setAttribute('data-state', 'busy');
        unlock(buf, phrase, opts.persist && opts.persist.checked).then(function (plain) {
          setStatus('Unlocked.', 'ok');
          opts.form.setAttribute('data-state', 'ok');
          opts.onOpen(plain, false);
        }).catch(function () {
          setStatus('That phrase did not unlock it. Check spelling and spaces.', 'err');
          opts.form.setAttribute('data-state', 'err');
          if (btn) btn.disabled = false;
          opts.input.select();
        });
      });
    });
  }

  /* Replace the current document with decrypted HTML (for sealed sub-pages). */
  function openDocument(bytes) {
    var html = new TextDecoder().decode(bytes);
    function swap() {
      // document.open() only replaces the page once the shell has finished loading.
      document.open();
      document.write(html);
      document.close();
    }
    if (document.readyState === 'complete') swap();
    else window.addEventListener('load', swap, { once: true });
  }

  /* Fetch an encrypted binary (e.g. the PDF) and decrypt it with the cached key. */
  function fetchSealed(url) {
    return fetch(url).then(function (r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.arrayBuffer();
    }).then(function (ab) {
      return tryCached(new Uint8Array(ab)).then(function (plain) {
        if (!plain) throw new Error('locked');
        return plain;
      });
    });
  }

  window.Gate = { mount: mount, lock: lock, openDocument: openDocument, fetchSealed: fetchSealed };
})();
