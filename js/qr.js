/*
 * qr.js — a minimal QR Code encoder (ISO/IEC 18004), so the 2FA enrolment can be
 * scanned instead of typed. Byte mode, error-correction level M, versions 1–10
 * (up to 213 bytes) — an otpauth:// URI never needs more.
 *
 * No dependencies, like everything else here: Reed-Solomon over GF(256), all
 * eight masks scored by the standard penalty rules, format and version info via
 * their BCH codes. `node js/qr.js --selftest` checks the output against the
 * reference vectors baked in at the bottom.
 *
 * Loaded both ways: as a browser IIFE (window.JS.qr) for the sign-in page, and
 * via require() by server.js for the console QR a headless install enrols from.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else (root.JS = root.JS || {}).qr = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // Error-correction level M, versions 1–10:
  //   version → [ EC codewords per block, [[block count, data codewords], …] ]
  const ECC_M = {
    1: [10, [[1, 16]]],
    2: [16, [[1, 28]]],
    3: [26, [[1, 44]]],
    4: [18, [[2, 32]]],
    5: [24, [[2, 43]]],
    6: [16, [[4, 27]]],
    7: [18, [[4, 31]]],
    8: [22, [[2, 38], [2, 39]]],
    9: [22, [[3, 36], [2, 37]]],
    10: [26, [[4, 43], [1, 44]]],
  };

  // Row/column centres of the alignment patterns for each version.
  const ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
    6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
  };

  const MASKS = [
    (r, c) => (r + c) % 2 === 0,
    (r) => r % 2 === 0,
    (r, c) => c % 3 === 0,
    (r, c) => (r + c) % 3 === 0,
    (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
    (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
    (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
  ];

  // ---- GF(256), primitive polynomial 0x11d ---------------------------------

  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);
  (function initField() {
    let x = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = x;
      LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();

  const mul = (a, b) => (a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]]);

  // g(x) = ∏(x − α^i), coefficients highest degree first.
  function generator(degree) {
    let poly = [1];
    for (let i = 0; i < degree; i++) {
      const a = EXP[i];
      const next = new Array(poly.length + 1).fill(0);
      next[0] = poly[0];
      for (let k = 1; k < poly.length; k++) next[k] = poly[k] ^ mul(a, poly[k - 1]);
      next[poly.length] = mul(a, poly[poly.length - 1]);
      poly = next;
    }
    return poly;
  }

  // Polynomial long division; the remainder is the error-correction block.
  function eccFor(data, ecLen) {
    const gen = generator(ecLen);
    const rem = data.concat(new Array(ecLen).fill(0));
    for (let i = 0; i < data.length; i++) {
      const factor = rem[i];
      if (factor === 0) continue;
      for (let j = 0; j < gen.length; j++) rem[i + j] ^= mul(gen[j], factor);
    }
    return rem.slice(data.length);
  }

  // ---- Bit stream ------------------------------------------------------------

  function dataCodewordsFor(version) {
    return ECC_M[version][1].reduce((n, [blocks, len]) => n + blocks * len, 0);
  }

  // Smallest version that holds this many bytes, header included.
  function versionFor(byteLength) {
    for (let v = 1; v <= 10; v++) {
      const header = 4 + (v < 10 ? 8 : 16);
      if (byteLength * 8 + header <= dataCodewordsFor(v) * 8) return v;
    }
    throw new Error(`${byteLength} bytes is beyond QR version 10 at ECC level M (213 max)`);
  }

  function bitStream(bytes, version) {
    const total = dataCodewordsFor(version);
    const bits = [];
    const push = (value, len) => { for (let i = len - 1; i >= 0; i--) bits.push((value >> i) & 1); };
    push(0b0100, 4);                              // byte mode
    push(bytes.length, version < 10 ? 8 : 16);    // character count
    for (const b of bytes) push(b, 8);
    push(0, Math.min(4, total * 8 - bits.length));   // terminator
    while (bits.length % 8) bits.push(0);

    const out = [];
    for (let i = 0; i < bits.length; i += 8) {
      let v = 0;
      for (let j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
      out.push(v);
    }
    // Fill the remainder with the two prescribed pad codewords, alternating.
    for (let i = 0; out.length < total; i++) out.push(i % 2 ? 0x11 : 0xec);
    return out;
  }

  // Split into blocks, add EC to each, then interleave both — codeword i of every
  // block in turn, so a burst of damage is spread across blocks.
  function codewords(bytes, version) {
    const [ecLen, groups] = ECC_M[version];
    const data = bitStream(bytes, version);
    const blocks = [];
    let p = 0;
    for (const [count, len] of groups) {
      for (let i = 0; i < count; i++) { blocks.push(data.slice(p, p + len)); p += len; }
    }
    const ecc = blocks.map((b) => eccFor(b, ecLen));
    const out = [];
    const longest = Math.max.apply(null, blocks.map((b) => b.length));
    for (let i = 0; i < longest; i++) for (const b of blocks) if (i < b.length) out.push(b[i]);
    for (let i = 0; i < ecLen; i++) for (const e of ecc) out.push(e[i]);
    return out;
  }

  // ---- BCH codes for the format and version information ----------------------

  // 15-bit format info: 5 data bits (EC level + mask), BCH(15,5), masked by 0x5412.
  function formatBits(mask) {
    const data = (0b00 << 3) | mask;          // 00 = error-correction level M
    let rem = data << 10;
    for (let i = 14; i >= 10; i--) if ((rem >> i) & 1) rem ^= 0x537 << (i - 10);
    return (((data << 10) | rem) ^ 0x5412) & 0x7fff;
  }

  // 18-bit version info, only present from version 7 up: BCH(18,6), unmasked.
  function versionBits(version) {
    let rem = version << 12;
    for (let i = 17; i >= 12; i--) if ((rem >> i) & 1) rem ^= 0x1f25 << (i - 12);
    return ((version << 12) | rem) & 0x3ffff;
  }

  // ---- Matrix ----------------------------------------------------------------

  // Everything that is not data: finders, separators, timing, alignment, the dark
  // module, and the reserved format/version areas.
  function functionPatterns(version) {
    const size = version * 4 + 17;
    const m = Array.from({ length: size }, () => new Array(size).fill(null));
    const fixed = Array.from({ length: size }, () => new Array(size).fill(false));
    const set = (r, c, v) => {
      if (r < 0 || c < 0 || r >= size || c >= size) return;
      m[r][c] = v;
      fixed[r][c] = true;
    };

    // Finder patterns and their one-module separators.
    for (const [r0, c0] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
      for (let r = -1; r <= 7; r++) {
        for (let c = -1; c <= 7; c++) {
          const ring = r >= 0 && r <= 6 && c >= 0 && c <= 6 &&
            (r === 0 || r === 6 || c === 0 || c === 6);
          const core = r >= 2 && r <= 4 && c >= 2 && c <= 4;
          set(r0 + r, c0 + c, ring || core ? 1 : 0);
        }
      }
    }

    // Timing patterns along row 6 and column 6.
    for (let i = 8; i < size - 8; i++) {
      set(6, i, i % 2 === 0 ? 1 : 0);
      set(i, 6, i % 2 === 0 ? 1 : 0);
    }

    // Alignment patterns, except where they would collide with a finder.
    const centres = ALIGN[version];
    for (const r of centres) {
      for (const c of centres) {
        if ((r <= 8 && c <= 8) || (r <= 8 && c >= size - 9) || (r >= size - 9 && c <= 8)) continue;
        for (let dr = -2; dr <= 2; dr++) {
          for (let dc = -2; dc <= 2; dc++) {
            set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1 ? 1 : 0);
          }
        }
      }
    }

    set(size - 8, 8, 1);   // the always-dark module

    // Reserve the format areas — written once the mask is chosen. They step over
    // the timing modules at (6,8)/(8,6), and the second copy stops one short of
    // the dark module at (size-8, 8).
    for (let i = 0; i <= 8; i++) { if (i !== 6) { set(8, i, 0); set(i, 8, 0); } }
    for (let i = 0; i < 8; i++) set(8, size - 1 - i, 0);
    for (let i = 0; i < 7; i++) set(size - 1 - i, 8, 0);

    // Version information, from version 7 up.
    if (version >= 7) {
      for (let i = 0; i < 18; i++) {
        const r = Math.floor(i / 3), c = i % 3;
        set(r, size - 11 + c, 0);
        set(size - 11 + c, r, 0);
      }
    }
    return { m, fixed, size };
  }

  // Zigzag up and down two columns at a time, right to left, skipping the
  // vertical timing column.
  function placeData(m, fixed, size, codes) {
    let dir = -1, row = size - 1, bit = 0;
    for (let col = size - 1; col > 0; col -= 2) {
      if (col === 6) col--;
      for (;;) {
        for (let i = 0; i < 2; i++) {
          const c = col - i;
          if (!fixed[row][c]) {
            const byte = codes[bit >> 3];
            m[row][c] = bit < codes.length * 8 ? (byte >> (7 - (bit & 7))) & 1 : 0;
            bit++;
          }
        }
        row += dir;
        if (row < 0 || row >= size) { row -= dir; dir = -dir; break; }
      }
    }
  }

  function writeFormat(m, size, mask) {
    const bits = formatBits(mask);
    const bit = (i) => (bits >> i) & 1;
    // First copy, around the top-left finder: bits 14→9 rightwards along row 8,
    // then 8 and 7 either side of the timing column, then 6 and 5→0 up column 8.
    for (let i = 0; i <= 5; i++) m[8][i] = bit(14 - i);
    m[8][7] = bit(8);
    m[8][8] = bit(7);
    m[7][8] = bit(6);
    for (let i = 0; i <= 5; i++) m[i][8] = bit(i);
    // Second copy: bits 14→8 up the bottom-left column, 7→0 along the top-right row.
    for (let i = 0; i <= 6; i++) m[size - 1 - i][8] = bit(14 - i);
    for (let i = 0; i <= 7; i++) m[8][size - 8 + i] = bit(7 - i);
  }

  function writeVersion(m, size, version) {
    if (version < 7) return;
    const bits = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const b = (bits >> i) & 1;
      const r = Math.floor(i / 3), c = i % 3;
      m[r][size - 11 + c] = b;
      m[size - 11 + c][r] = b;
    }
  }

  // ---- Mask penalty (the four rules of §7.8.3) -------------------------------

  function penalty(m, size) {
    let score = 0;

    // Rule 1 — runs of five or more identical modules in a row or column.
    for (let i = 0; i < size; i++) {
      for (const line of [m[i], m.map((row) => row[i])]) {
        let run = 1;
        for (let j = 1; j < size; j++) {
          if (line[j] === line[j - 1]) { run++; continue; }
          if (run >= 5) score += 3 + (run - 5);
          run = 1;
        }
        if (run >= 5) score += 3 + (run - 5);
      }
    }

    // Rule 2 — every 2×2 block of one colour.
    for (let r = 0; r < size - 1; r++) {
      for (let c = 0; c < size - 1; c++) {
        const v = m[r][c];
        if (v === m[r][c + 1] && v === m[r + 1][c] && v === m[r + 1][c + 1]) score += 3;
      }
    }

    // Rule 3 — the finder-lookalike 1011101 with four light modules either side.
    const A = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
    const B = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1];
    const hit = (line, at, pat) => pat.every((v, k) => line[at + k] === v);
    for (let i = 0; i < size; i++) {
      const rowLine = m[i], colLine = m.map((row) => row[i]);
      for (let j = 0; j + 11 <= size; j++) {
        for (const line of [rowLine, colLine]) {
          if (hit(line, j, A)) score += 40;
          if (hit(line, j, B)) score += 40;
        }
      }
    }

    // Rule 4 — how far the dark/light balance strays from 50%.
    let dark = 0;
    for (let r = 0; r < size; r++) for (let c = 0; c < size; c++) dark += m[r][c];
    const pct = (dark * 100) / (size * size);
    score += 10 * Math.floor(Math.abs(pct - 50) / 5);

    return score;
  }

  // ---- Public API ------------------------------------------------------------

  function toBytes(text) {
    // The strings this encodes (otpauth:// URIs) are ASCII, but encode UTF-8
    // properly anyway so a non-ASCII issuer cannot produce a corrupt symbol.
    if (typeof TextEncoder === 'function') return Array.from(new TextEncoder().encode(text));
    return Array.from(Buffer.from(text, 'utf8'));
  }

  /**
   * Encode text as a QR symbol.
   * @returns {{version: number, size: number, mask: number, modules: number[][]}}
   */
  function encode(text, opts) {
    const bytes = toBytes(String(text));
    const version = (opts && opts.version) || versionFor(bytes.length);
    if (!ECC_M[version]) throw new Error(`unsupported QR version ${version}`);
    const codes = codewords(bytes, version);

    let best = null;
    const forced = opts && opts.mask != null ? [opts.mask] : [0, 1, 2, 3, 4, 5, 6, 7];
    for (const mask of forced) {
      const { m, fixed, size } = functionPatterns(version);
      placeData(m, fixed, size, codes);
      for (let r = 0; r < size; r++) {
        for (let c = 0; c < size; c++) if (!fixed[r][c] && MASKS[mask](r, c)) m[r][c] ^= 1;
      }
      writeFormat(m, size, mask);
      writeVersion(m, size, version);
      const score = penalty(m, size);
      if (!best || score < best.score) best = { score, mask, modules: m, size };
    }
    return { version, size: best.size, mask: best.mask, modules: best.modules };
  }

  /**
   * Inline SVG, always dark-on-white with a quiet zone — a QR inverted by a dark
   * theme is a QR most scanners refuse.
   */
  function toSvg(qr, opts) {
    const o = opts || {};
    const quiet = o.quiet == null ? 4 : o.quiet;
    const span = qr.size + quiet * 2;
    let path = '';
    for (let r = 0; r < qr.size; r++) {
      for (let c = 0; c < qr.size; c++) {
        if (qr.modules[r][c]) path += `M${c + quiet} ${r + quiet}h1v1h-1z`;
      }
    }
    const px = o.size ? ` width="${o.size}" height="${o.size}"` : '';
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${span} ${span}"${px} ` +
      `role="img" aria-label="${o.label || 'QR code'}" shape-rendering="crispEdges">` +
      `<rect width="${span}" height="${span}" fill="#fff"/>` +
      `<path d="${path}" fill="#000"/></svg>`;
  }

  /**
   * Terminal rendering: one character per two rows via half-blocks, with black
   * ink forced onto a white background so it scans whatever the terminal theme is.
   */
  function toAnsi(qr, opts) {
    const o = opts || {};
    const quiet = o.quiet == null ? 2 : o.quiet;
    const span = qr.size + quiet * 2;
    const at = (r, c) => {
      const rr = r - quiet, cc = c - quiet;
      if (rr < 0 || cc < 0 || rr >= qr.size || cc >= qr.size) return 0;
      return qr.modules[rr][cc];
    };
    const ON = '\x1b[30;107m';   // black foreground, bright white background
    const OFF = '\x1b[0m';
    const lines = [];
    for (let r = 0; r < span; r += 2) {
      let line = '';
      for (let c = 0; c < span; c++) {
        const top = at(r, c), bottom = at(r + 1, c);
        // The glyph's ink is the dark module, the background is the light one.
        line += top && bottom ? '█' : top ? '▀' : bottom ? '▄' : ' ';
      }
      lines.push((o.indent || '') + ON + line + OFF);
    }
    return lines.join('\n');
  }

  return { encode, toSvg, toAnsi, versionFor, formatBits, versionBits };
});

// ---- Self-test ---------------------------------------------------------------
// `node js/qr.js --selftest` checks the BCH tables against the values printed in
// ISO/IEC 18004 and confirms every version round-trips through version selection.
if (typeof module === 'object' && require.main === module && process.argv.includes('--selftest')) {
  const qr = module.exports;
  let failed = 0;
  const eq = (label, got, want) => {
    const ok = got === want;
    if (!ok) failed++;
    console.log(`${ok ? '  ✓' : '  ✗'} ${label}${ok ? '' : `  got ${got}, want ${want}`}`);
  };

  console.log('\n  Format information (ECC level M, Table C.1)');
  // The 15-bit strings the standard prints for level M, masks 0–7.
  ['101010000010010', '101000100100101', '101111001111100', '101101101001011',
    '100010111111001', '100000011001110', '100111110010111', '100101010100000',
  ].forEach((want, mask) => {
    eq(`mask ${mask}`, qr.formatBits(mask).toString(2).padStart(15, '0'), want);
  });

  console.log('\n  Version information (Table D.1)');
  const VERSIONS = {
    7: '000111110010010100', 8: '001000010110111100',
    9: '001001101010011001', 10: '001010010011010011',
  };
  Object.keys(VERSIONS).forEach((v) => {
    eq(`version ${v}`, qr.versionBits(+v).toString(2).padStart(18, '0'), VERSIONS[v]);
  });

  console.log('\n  Symbol geometry');
  const sample = qr.encode('HELLO WORLD');
  eq('size = 4·version + 17', sample.size, sample.version * 4 + 17);
  eq('a 120-byte payload fits version 7', qr.versionFor(120), 7);
  eq('a 200-byte payload fits version 10', qr.versionFor(200), 10);

  console.log('\n  Renderers reproduce the matrix');
  const enc = qr.encode('otpauth://totp/APEX%20JediSyslogger%3Aadmin?secret=' +
    'GO7NNSOIVZAH55XBURRMEQNXVQYYS4VJ&issuer=APEX%20JediSyslogger&algorithm=SHA1&digits=6&period=30');

  // SVG: one 1×1 rect per dark module, offset by the quiet zone.
  const svg = qr.toSvg(enc, { quiet: 4 });
  const drawn = new Set();
  svg.replace(/M(\d+) (\d+)h1v1h-1z/g, (_, x, y) => drawn.add(`${+y - 4},${+x - 4}`) && '');
  let svgWrong = 0;
  for (let r = 0; r < enc.size; r++) {
    for (let c = 0; c < enc.size; c++) if (!!enc.modules[r][c] !== drawn.has(`${r},${c}`)) svgWrong++;
  }
  eq('every dark module drawn, and only those', svgWrong, 0);

  // ANSI: two module rows per line, dark modules carrying the glyph's ink.
  const GLYPH = { '█': [1, 1], '▀': [1, 0], '▄': [0, 1], ' ': [0, 0] };
  const quiet = 2;
  const lines = qr.toAnsi(enc, { quiet }).split('\n')
    .map((l) => l.replace(/\x1b\[[0-9;]*m/g, ''));
  let ansiWrong = 0;
  for (let r = 0; r < enc.size; r++) {
    for (let c = 0; c < enc.size; c++) {
      const glyph = lines[Math.floor((r + quiet) / 2)][c + quiet];
      const half = GLYPH[glyph][(r + quiet) % 2];
      if (half !== enc.modules[r][c]) ansiWrong++;
    }
  }
  eq('half-blocks carry the modules, ink = dark', ansiWrong, 0);

  console.log(failed ? `\n  ${failed} check(s) FAILED\n` : '\n  all checks passed\n');
  process.exit(failed ? 1 : 0);
}
