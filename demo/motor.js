/*
 * MOTOR da demonstração online: o mesmo simulador de teste/mock.js, adaptado para rodar no NAVEGADOR.
 * Finge ser o Google (planilhas, Drive, cache…) e roda o código de verdade do sistema (gas.js) com dados de mentira.
 * Tudo fica na memória desta página: recarregar = volta ao começo.
 */
(function () {
  const pad = n => String(n).padStart(2, '0');
  const utf8 = s => Array.from(new TextEncoder().encode(String(s)));
  const b64dec = s => Array.from(atob(String(s).replace(/\s/g, '')), c => c.charCodeAt(0));
  const b64enc = b => { let s = ''; const a = Array.from(b, x => x & 255); for (let i = 0; i < a.length; i += 8192) s += String.fromCharCode.apply(null, a.slice(i, i + 8192)); return btoa(s); };
  // SHA-256 (as senhas da demonstração passam pelo mesmo hash do sistema)
  function sha256(bytes) {
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const m = bytes.slice(), l = m.length * 8; m.push(0x80); while (m.length % 64 !== 56) m.push(0);
    for (let i = 7; i >= 0; i--) m.push(i > 3 ? 0 : (l >>> (i * 8)) & 255);
    const w = new Array(64), r = (x, n) => (x >>> n) | (x << (32 - n));
    for (let o = 0; o < m.length; o += 64) {
      for (let i = 0; i < 16; i++) w[i] = (m[o + i * 4] << 24) | (m[o + i * 4 + 1] << 16) | (m[o + i * 4 + 2] << 8) | m[o + i * 4 + 3];
      for (let i = 16; i < 64; i++) { const s0 = r(w[i - 15], 7) ^ r(w[i - 15], 18) ^ (w[i - 15] >>> 3), s1 = r(w[i - 2], 17) ^ r(w[i - 2], 19) ^ (w[i - 2] >>> 10); w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0; }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (r(e, 6) ^ r(e, 11) ^ r(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0, t2 = ((r(a, 2) ^ r(a, 13) ^ r(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0; H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    const out = []; H.forEach(x => out.push((x >>> 24) & 255, (x >>> 16) & 255, (x >>> 8) & 255, x & 255)); return out;
  }

  function deJSON(v) {
    if (v && typeof v === 'object') {
      if (v.d) { const [y, m, d] = v.d.split('-').map(Number); return new Date(y, m - 1, d); }
      if (v.t) { const [h, mi] = v.t.split(':').map(Number); const x = new Date(1899, 11, 30, h, mi); x._hora = v.t; return x; }
      if (v.dur) { const x = new Date(1899, 11, 30); x._hora = v.dur; return x; }
    }
    return v === null || v === undefined ? '' : v;
  }
  function exibir(v) {
    if (v instanceof Date) return v._hora || (pad(v.getDate()) + '/' + pad(v.getMonth() + 1) + '/' + v.getFullYear());
    if (typeof v === 'boolean') return v ? 'TRUE' : 'FALSE';
    if (typeof v === 'string' && /^\d{1,2}:\d{2}$/.test(v)) return v;
    return v === '' ? '' : String(v);
  }
  class Aba {
    constructor(nome, linhas) { this.nome = nome; this.m = linhas.map(r => r.map(deJSON)); const w = Math.max(...this.m.map(r => r.length)); this.m.forEach(r => { while (r.length < w) r.push(''); }); }
    getLastRow() { for (let i = this.m.length - 1; i >= 0; i--) if (this.m[i].some(c => c !== '' && c !== false)) return i + 1; return 0; }
    getLastColumn() { return this.m[0].length; }
    getDataRange() { return this.getRange(1, 1, this.m.length, this.m[0].length); }
    getRange(r, c, nr, nc) {
      if (typeof r === 'string') { const m = r.match(/([A-Z]+)(\d+)/); const col = m[1].charCodeAt(0) - 64; return this.getRange(+m[2], col, 1, 1); }
      nr = nr || 1; nc = nc || 1; const aba = this;
      const garantir = () => { while (aba.m.length < r + nr - 1) aba.m.push(aba.m[0].map(() => '')); };
      return {
        getValues() { garantir(); return aba.m.slice(r - 1, r - 1 + nr).map(l => l.slice(c - 1, c - 1 + nc)); },
        getDisplayValues() { return this.getValues().map(l => l.map(exibir)); },
        getDisplayValue() { return exibir(this.getValues()[0][0]); },
        getValue() { return this.getValues()[0][0]; },
        setValue(v) { garantir(); if (typeof v === 'string' && /^\d{1,2}:\d{2}$/.test(v)) { const x = new Date(1899, 11, 30); x._hora = v; v = x; } aba.m[r - 1][c - 1] = v; return this; },
        setValues(vs) { garantir(); vs.forEach((l, i) => l.forEach((v, j) => { aba.m[r - 1 + i][c - 1 + j] = v; })); return this; },
        setNumberFormat() { return this; },
        clearContent() { garantir(); for (let i = 0; i < nr; i++) for (let j = 0; j < nc; j++) aba.m[r - 1 + i][c - 1 + j] = ''; return this; }
      };
    }
    deleteRows(a, n) { this.m.splice(a - 1, n); }
    setName(n) { this.nome = n; return this; }
    appendRow(l) { const r = this.getLastRow() + 1; while (this.m.length < r) this.m.push(this.m[0].map(() => '')); l.forEach((v, j) => this.m[r - 1][j] = v); }
  }

  const PLAN = {}; window.PLAN = PLAN;
  Object.keys(window.DADOS).forEach(k => { PLAN[k] = {}; Object.keys(window.DADOS[k]).forEach(a => PLAN[k][a] = new Aba(a, window.DADOS[k][a])); });
  const IDMAP = window.IDMAP = {}, cache = new Map(), novas = window.__planilhasNovas = {};

  window.SpreadsheetApp = {
    openById(id) { if (novas[id]) return novas[id]; const k = IDMAP[id]; if (!k) throw new Error('Sem acesso à planilha ' + id); return { getSheetByName: n => PLAN[k][n] || null, insertSheet: n => (PLAN[k][n] = new Aba(n, [['']])) }; },
    create(nome) { const id = 'SS' + Object.keys(novas).length; const abas = [new Aba('Página1', [['']])];
      const ss = { nome, abas, getId: () => id, getUrl: () => 'https://docs/' + id, getSheets: () => abas, getSheetByName: n => abas.find(a => a.nome === n) || null,
        insertSheet: n => { const a = new Aba(n, [['']]); abas.push(a); return a; }, deleteSheet: a => { abas.splice(abas.indexOf(a), 1); } };
      novas[id] = ss; return ss; }
  };
  window.CacheService = { getScriptCache: () => ({ get: k => cache.has(k) ? cache.get(k) : null, put: (k, v) => cache.set(k, v), remove: k => cache.delete(k) }) };
  window.LockService = { getScriptLock: () => ({ tryLock: () => true, releaseLock: () => { } }) };
  window.PropertiesService = (() => { const p = new Map(); const o = { getProperty: k => p.has(k) ? p.get(k) : null, setProperty: (k, v) => { p.set(k, String(v)); return o; }, deleteProperty: k => { p.delete(k); return o; }, getProperties: () => Object.fromEntries(p) }; return { getScriptProperties: () => o }; })();
  window.Utilities = {
    DigestAlgorithm: { SHA_256: 'sha256' }, Charset: { UTF_8: 'utf8' },
    computeDigest: (a, s) => sha256(utf8(s)).map(b => b > 127 ? b - 256 : b),
    getUuid: () => (window.crypto && crypto.randomUUID) ? crypto.randomUUID() : 'u' + Date.now().toString(36) + Math.random().toString(36).slice(2),
    formatDate: (d, tz, f) => f.replace('yyyy', d.getFullYear()).replace('MM', pad(d.getMonth() + 1)).replace('dd', pad(d.getDate())).replace('HH', pad(d.getHours())).replace('mm', pad(d.getMinutes())).replace('ss', pad(d.getSeconds())),
    base64Decode: s => b64dec(s), base64Encode: b => b64enc(b),
    newBlob: (b, m, n) => ({ b, m, n })
  };
  window.Session = { getEffectiveUser: () => ({ getEmail: () => 'dono@demonstracao' }), getActiveUser: () => ({ getEmail: () => 'dono@demonstracao' }) };
  window.DriveApp = (() => {
    let seq = 0; const ARQ = {}, PASTAS = {};
    const it = l => { let i = 0; return { hasNext: () => i < l.length, next: () => l[i++] }; };
    const mkPasta = (nome, pai, idFixo) => {
      const id = idFixo || 'P' + (++seq);
      const p = { nome, files: [], sub: {}, getId: () => id, getName: () => nome, getUrl: () => 'https://drive/' + nome, setDescription() { }, getParents: () => it(pai ? [pai] : []),
        getFoldersByName: n => it(p.sub[n] ? [p.sub[n]] : []), getFolders: () => it(Object.values(p.sub)),
        createFolder: n => (p.sub[n] = mkPasta(n, p)),
        createFile(bl) { let desc = ''; const fid = 'F' + (++seq); const f = { getId: () => fid, getName: () => bl.n, getThumbnail: () => null, getUrl: () => 'https://drive/f/' + bl.n, getDateCreated: () => new Date(),
            getMimeType: () => bl.m || 'application/pdf', getSize: () => (bl.b || []).length, getParents: () => it([p]),
            setDescription(x) { desc = x; }, getDescription: () => desc, getBlob: () => ({ getBytes: () => bl.b || [] }), setSharing() { }, setTrashed() { p.files = p.files.filter(x => x !== f); delete ARQ[fid]; } };
          ARQ[fid] = f; p.files.push(f); return f; },
        getFiles() { return it(p.files.slice()); },
        getFilesByName(n) { return it(p.files.filter(f => f.getName() === n)); } };
      PASTAS[id] = p; return p; };
    const finPasta = mkPasta('01 Financeiro', null, 'PASTA_FIN'), raiz = mkPasta('Meu Drive', null, 'RAIZ');
    return { getFolderById: id => PASTAS[id] || mkPasta('raiz-' + id, null, id), getRootFolder: () => raiz, createFolder: n => raiz.createFolder(n),
      getFileById: id => ARQ[id] || { getId: () => id, getParents: () => it([finPasta]), moveTo(p) { return this; }, setSharing() { return this; }, makeCopy() { return { getId: () => 'COPIA' }; } },
      Access: { ANYONE_WITH_LINK: 1 }, Permission: { VIEW: 1 }, _arq: ARQ };
  })();
  // os PDFs da demonstração são o próprio HTML do documento (abre como página)
  window.HtmlService = { createHtmlOutput: h => ({ getAs: () => ({ n: '', b: utf8(h), m: 'application/pdf', setName(x) { this.n = x; return this; } }) }) };
  window.ContentService = { createTextOutput: t => ({ t, setMimeType() { return this; } }), MimeType: { JSON: 'json' } };
  window.UrlFetchApp = { fetch: () => { throw new Error('Sem internet na demonstração.'); } };
})();
