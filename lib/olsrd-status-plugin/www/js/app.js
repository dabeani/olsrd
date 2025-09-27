// JSON polyfill for older browsers
if (!window.JSON) {
  window.JSON = {
    parse: function(s) {
      try {
        return eval('(' + s + ')');
      } catch (e) {
        throw new Error('Invalid JSON');
      }
    },
    stringify: function(obj) {
      var t = typeof obj;
      if (t !== "object" || obj === null) {
        if (t === "string") return '"' + obj + '"';
        return String(obj);
      }
      var json = [];
      var arr = (obj && obj.constructor === Array);
      for (var k in obj) {
        if (obj.hasOwnProperty && obj.hasOwnProperty(k)) {
          json.push((arr ? "" : '"' + k + '":') + window.JSON.stringify(obj[k]));
        }
      }
      return (arr ? "[" : "{") + json.join(',') + (arr ? "]" : "}");
    }
  };
}

// Object.keys polyfill for older browsers
if (!Object.keys) {
  Object.keys = function(obj) {
    if (!obj) return [];
    var keys = [];
    for (var key in obj) {
      if (obj.hasOwnProperty && obj.hasOwnProperty(key)) {
        keys.push(key);
      }
    }
    return keys;
  };
}

// Array.isArray polyfill for older browsers
if (!Array.isArray) {
  Array.isArray = function(arg) {
    return Object.prototype.toString.call(arg) === '[object Array]';
  };
}

// Promise polyfill for older browsers
if (!window.Promise) {
  window.Promise = function(executor) {
    var self = this;
    self.status = 'pending';
    self.value = undefined;
    self.reason = undefined;
    self.onFulfilled = [];
    self.onRejected = [];

    function resolve(value) {
      if (self.status === 'pending') {
        self.status = 'fulfilled';
        self.value = value;
        self.onFulfilled.forEach(function(fn){ fn(value); });
      }
    }
    function reject(reason) {
      if (self.status === 'pending') {
        self.status = 'rejected';
        self.reason = reason;
        self.onRejected.forEach(function(fn){ fn(reason); });
      }
    }
    try {
      executor(resolve, reject);
    } catch (e) {
      reject(e);
    }
  };

  window.Promise.prototype.then = function(onFulfilled, onRejected) {
    var self = this;
    return new window.Promise(function(resolve, reject) {
      function handleFulfilled(value) {
        try {
          if (typeof onFulfilled === 'function') {
            var result = onFulfilled(value);
            if (result && typeof result.then === 'function') {
              result.then(resolve, reject);
            } else {
              resolve(result);
            }
          } else {
            resolve(value);
          }
        } catch (e) { reject(e); }
      }
      function handleRejected(reason) {
        try {
          if (typeof onRejected === 'function') {
            var result = onRejected(reason);
            if (result && typeof result.then === 'function') {
              result.then(resolve, reject);
            } else {
              resolve(result);
            }
          } else {
            reject(reason);
          }
        } catch (e) { reject(e); }
      }
      if (self.status === 'fulfilled') { handleFulfilled(self.value); }
      else if (self.status === 'rejected') { handleRejected(self.reason); }
      else { self.onFulfilled.push(handleFulfilled); self.onRejected.push(handleRejected); }
    });
  };

  window.Promise.prototype.catch = function(onRejected) { return this.then(null, onRejected); };
  window.Promise.resolve = function(value) { return new window.Promise(function(resolve) { resolve(value); }); };
  window.Promise.all = function(promises) {
    return new window.Promise(function(resolve, reject) {
      var results = []; var completed = 0; var total = promises.length;
      if (total === 0) { resolve(results); return; }
      promises.forEach(function(promise, index) {
        promise.then(function(value) { results[index] = value; completed++; if (completed === total) resolve(results); }, reject);
      });
    });
  };
}

// Fetch polyfill for older browsers
if (!window.fetch) {
  window.fetch = function(url, options) {
    options = options || {};
    return new Promise(function(resolve, reject) {
      var xhr = new XMLHttpRequest();
      xhr.open(options.method || 'GET', url, true);
      if (options.headers) {
        for (var header in options.headers) {
          xhr.setRequestHeader(header, options.headers[header]);
        }
      }
      // Add cache control header if cache option is specified
      if (options.cache === 'no-store') {
        xhr.setRequestHeader('Cache-Control', 'no-cache');
      }
      xhr.onreadystatechange = function() {
        if (xhr.readyState === 4) {
          var response = {
            ok: xhr.status >= 200 && xhr.status < 300,
            status: xhr.status,
            statusText: xhr.statusText,
            text: function() { return Promise.resolve(xhr.responseText); },
            json: function() { return Promise.resolve(JSON.parse(xhr.responseText)); }
          };
          if (response.ok) {
            resolve(response);
          } else {
            reject(new Error('HTTP ' + xhr.status));
          }
        }
      };
      xhr.onerror = function() { reject(new Error('Network error')); };
      xhr.send(options.body);
    });
  };
}

// Global td helper: create a TD element. By default it sets textContent to avoid HTML injection.
// Pass second argument `true` to allow HTML (legacy) - but we now avoid innerHTML and always create safe text nodes.
function td(val/*, allowHtml - legacy */) {
  var td = document.createElement('td');
  if (typeof val === 'undefined' || val === null) {
    td.textContent = '';
    return td;
  }
  // If caller passed an HTML fragment (legacy behavior), parse it safely and
  // append nodes instead of assigning innerHTML. We detect HTML heuristically
  // by looking for angle-brackets. This preserves previous behavior where
  // certain call-sites passed '<a..>' or '<span..>' strings.
  if (typeof val === 'string' && /<[^>]+>/.test(val)) {
    try {
      var parser = new DOMParser();
      var doc = parser.parseFromString(val || '', 'text/html');
      Array.prototype.slice.call(doc.body.childNodes).forEach(function(n){ td.appendChild(n.cloneNode(true)); });
      return td;
    } catch(e) {
      // fallthrough to textContent fallback
    }
  }
  td.textContent = String(val);
  return td;
}

// Safely remove all children from an element (avoids innerHTML = '')
function clearChildren(el) {
  try { if (!el) return; while (el.firstChild) el.removeChild(el.firstChild); } catch(e){}
}

// Footer pending-request counter: show the number of in-flight fetches
(function(){
  var _pendingFetches = 0;
  function updateFooterPending() {
    try {
  // keep internal pending counter for diagnostics but the UI now shows
  // last-request text instead of a numeric pending badge.
  var el = document.getElementById('footer-pending');
      if (!el) return;
      el.textContent = String(_pendingFetches);
  var badge = el;
  if (_pendingFetches > 0) badge.classList.add('nonzero'); else badge.classList.remove('nonzero');
    } catch(e) {}
  }

  var origFetch = window.fetch;
  window.fetch = function(url, opts) {
    try {
      _pendingFetches++; updateFooterPending();
      // turn on the footer dot to indicate activity
      try { var fd = document.getElementById('footer-dot'); if (fd) { fd.classList.remove('footer-dot-off'); fd.classList.add('footer-dot-on'); } } catch(e) {}
      // Record last requested endpoint in footer (strip query string and host)
      try {
        var u = String(url || '');
        // If a Request object was passed, extract its url
        if (typeof url === 'object' && url && url.url) u = url.url;
        // Remove scheme and host if present
        var path = u.replace(/^[a-z]+:\/\/[0-9a-zA-Z.:-]+/i, '');
        // Strip query string and hash
        path = path.split('?')[0].split('#')[0];
        // Trim leading slashes
        path = path.replace(/^\/+/,'');
        // For readability show only last path segment(s) up to two levels
        var parts = path.split('/').filter(function(p){ return p && p.length; });
        var disp = parts.length === 0 ? '/' : (parts.length <= 2 ? parts.join('/') : parts.slice(-2).join('/'));
        // write via helper so truncation tooltips are handled
        try { setFooterText('footer-last-request', disp); } catch(e) { var lr = document.getElementById('footer-last-request'); if (lr) lr.textContent = disp; }
      } catch(e) {}
    } catch(e) {}
    return origFetch.apply(this, arguments).then(function(resp){
      try { _pendingFetches = Math.max(0,_pendingFetches-1); updateFooterPending(); } catch(e) {}
      // flip footer dot off after a short delay so rapid requests don't flicker
      try { setTimeout(function(){ var fd=document.getElementById('footer-dot'); if(fd){ fd.classList.remove('footer-dot-on'); fd.classList.add('footer-dot-off'); } }, 180); } catch(e) {}
      // update compact last-updated mirror in footer immediately when a response returns
  try { if (resp && resp.ok) { var now = new Date().toLocaleString(); try { setFooterText('footer-last-updated', now); } catch(e) { var fel = document.getElementById('footer-last-updated'); if (fel) fel.textContent = now; } var main = document.getElementById('last-updated'); if (main) main.textContent = now; } } catch(e) {}
      return resp;
    }).catch(function(err){
      try { _pendingFetches = Math.max(0,_pendingFetches-1); updateFooterPending(); } catch(e) {}
      try { setTimeout(function(){ var fd=document.getElementById('footer-dot'); if(fd){ fd.classList.remove('footer-dot-on'); fd.classList.add('footer-dot-off'); } }, 180); } catch(e) {}
      throw err;
    });
  };
})();

// Footer diagnostics drawer: open/close and populate diagnostics
(function(){
  function el(id){ return document.getElementById(id); }
  // Tolerant JSON parser: normalize raw control chars inside strings and
  // extract top-level JSON candidates from noisy text
  function safeParseJson(text){
    try { return JSON.parse(text); } catch(e) {}
    function normalize(s){
      var out = ''; var inStr = false, esc = false;
      for (var i=0;i<s.length;i++){ var ch = s.charAt(i);
        if (inStr){ if (esc) { out += ch; esc = false; continue; } if (ch === '\\') { out += ch; esc = true; continue; } if (ch === '\n' || ch === '\r') { out += '\\n'; continue; } if (ch === '\t') { out += '\\t'; continue; } if (ch === '"') { inStr = false; out += ch; continue; } out += ch; }
        else { if (ch === '"') { inStr = true; out += ch; continue; } out += ch; }
      }
      return out;
    }
    try { return JSON.parse(normalize(String(text||''))); } catch(e2){}
    function extractCandidates(s){
      var out = []; var inStr=false, esc=false, start=-1, depth=0;
      for (var i=0;i<s.length;i++){ var c=s.charAt(i);
        if (inStr){ if (esc) { esc=false; continue; } if (c==='\\') { esc=true; continue; } if (c==='"') { inStr=false; } continue; }
        if (c==='"'){ inStr=true; continue; }
        if (depth===0){ if (c==='{'||c==='['){ start=i; depth=1; } }
        else { if (c==='{'||c==='[') depth++; else if (c==='}'||c===']'){ depth--; if (depth===0 && start>=0){ out.push(s.substring(start,i+1)); start=-1; } } }
      }
      return out;
    }
    try {
      var cands = extractCandidates(String(text||''));
      var keys = ['globals','versions','capabilities','summary','fetch_debug'];
      var best=null, bestScore=-1;
      for (var i=0;i<cands.length;i++){ try { var o = JSON.parse(cands[i]); if (o && typeof o === 'object' && !Array.isArray(o)){ var score=0; for (var k=0;k<keys.length;k++) if (Object.prototype.hasOwnProperty.call(o, keys[k])) score++; if (score>bestScore){ bestScore=score; best=o; } } } catch(_){} }
      if (best) return best;
      for (var j=cands.length-1;j>=0;j--){ try { return JSON.parse(cands[j]); } catch(_){} }
    } catch(e3){}
    throw new Error('Invalid JSON');
  }

  // Extract a single top-level key's value from a noisy JSON text. Returns parsed value or null.
  function extractTopLevelKey(text, key){
    try {
      if (!text || !key) return null;
      var idx = text.indexOf('"' + key + '"');
      if (idx === -1) return null;
      var colon = text.indexOf(':', idx);
      if (colon === -1) return null;
      var i = colon + 1; while (i < text.length && /[\s\n\r\t]/.test(text.charAt(i))) i++;
      var ch = text.charAt(i);
      if (ch === '{' || ch === '[') {
        var start = i; var depth = 0; var inStr = false; var esc = false;
        for (var j = i; j < text.length; j++){
          var c = text.charAt(j);
          if (inStr) {
            if (esc) { esc = false; continue; }
            if (c === '\\') { esc = true; continue; }
            if (c === '"') { inStr = false; }
            continue;
          } else {
            if (c === '"') { inStr = true; continue; }
            if (c === '{' || c === '[') { depth++; continue; }
            if (c === '}' || c === ']') { depth--; if (depth === 0) { var cand = text.substring(start, j+1); try { return safeParseJson(cand); } catch(e){ return null; } } }
          }
        }
      } else {
        var start = i; var j = i; for (; j < text.length; j++) { var cc = text.charAt(j); if (cc === ',' || cc === '}' || cc === ']') break; }
        var cand = text.substring(start, j).trim(); try { return JSON.parse(cand); } catch(e){ return null; }
      }
    } catch(e) { return null; }
    return null;
  }
  function showDiagnostics(open){
    var panel = el('footer-diagnostics-panel');
    if(!panel) return;
    if(open){ panel.setAttribute('aria-hidden','false'); panel.style.display='block'; }
    else { panel.setAttribute('aria-hidden','true'); /* hide after transition */ setTimeout(function(){ try{ panel.style.display='none'; }catch(e){} }, 300); }
  }

  function makeBox(title){
    var box = document.createElement('div'); box.className='diag-box';
    var t = document.createElement('div'); t.className='diag-title'; t.textContent = title; box.appendChild(t);
    var body = document.createElement('div'); body.className='diag-body'; box.appendChild(body);
    return {box:box, body:body};
  }

  // Collapsible box with copy button (returns {wrap, body, copyBtn})
  function makeCollapsibleBox(title){
    var wrap = document.createElement('div'); wrap.className = 'diag-box';
    var header = document.createElement('div'); header.style.display='flex'; header.style.alignItems='center'; header.style.justifyContent='space-between';
    var t = document.createElement('div'); t.className='diag-title'; t.textContent = title; header.appendChild(t);
    var btns = document.createElement('div');
    var copyBtn = document.createElement('button'); copyBtn.className='btn btn-xs btn-default'; copyBtn.textContent='Copy'; copyBtn.style.marginLeft='6px';
    btns.appendChild(copyBtn);
    header.appendChild(btns);
    wrap.appendChild(header);
    var body = document.createElement('div'); body.className='diag-body'; wrap.appendChild(body);
    return {wrap:wrap, body:body, copyBtn:copyBtn};
  }

  function kvRow(k,v){
    var row = document.createElement('div'); row.className='diag-row';
    var key = document.createElement('div'); key.className='diag-key'; key.textContent = k; row.appendChild(key);
    var val = document.createElement('div'); val.className='diag-value';
    try { if (typeof v === 'object') val.textContent = JSON.stringify(v, null, 2); else val.textContent = String(v); } catch(e){ val.textContent = String(v); }
    row.appendChild(val);
    return row;
  }

  // New compact diagnostics renderer: flatten all keys and print key=val per line
  function flattenObject(obj, prefix) {
    var out = [];
    prefix = prefix || '';
    if (obj === null || typeof obj === 'undefined') {
      out.push(prefix + '=' + String(obj));
      return out;
    }
    if (typeof obj !== 'object') {
      out.push(prefix + '=' + String(obj));
      return out;
    }
    if (Array.isArray(obj)) {
      if (obj.length === 0) { out.push(prefix + '=[]'); return out; }
      for (var i = 0; i < obj.length; i++) {
        var p = prefix + '[' + i + ']';
        out = out.concat(flattenObject(obj[i], p));
      }
      return out;
    }
    var keys = Object.keys(obj).sort();
    if (keys.length === 0) { out.push(prefix + '={}'); return out; }
    for (var ki = 0; ki < keys.length; ki++) {
      var k = keys[ki];
      var val = obj[k];
      var pfx = prefix ? (prefix + '.' + k) : k;
      if (val === null || typeof val === 'undefined') { out.push(pfx + '=' + String(val)); }
      else if (typeof val === 'object') { out = out.concat(flattenObject(val, pfx)); }
      else { out.push(pfx + '=' + String(val)); }
    }
    return out;
  }

  function renderDiagnostics(payloads){
    var body = el('footer-diagnostics-body'); if(!body) return;
    // also populate status tab versions string (if present)
    try {
      var sEl = document.getElementById('status-versions-string');
      if (sEl) {
        var s = null;
        try { if (payloads && payloads.versions && payloads.versions.versions_string) s = payloads.versions.versions_string; } catch(e){}
        if (!s) try { if (payloads && payloads.versions_string) s = payloads.versions_string; } catch(e){}
        if (s) { sEl.textContent = String(s); } else { sEl.textContent = '\u00A0'; }
      }
    } catch(e) {}
    // set prominent versions/timestamp if available
    try {
      var vsEl = document.getElementById('diag-versions-string');
      if (vsEl) {
        var vs = null;
        try { if (payloads && payloads.versions && payloads.versions.versions_string) vs = payloads.versions.versions_string; } catch(e){}
        if (!vs) try { if (payloads && payloads.versions_string) vs = payloads.versions_string; } catch(e){}
        if (vs) { vsEl.textContent = String(vs); vsEl.style.display = ''; }
        else { vsEl.textContent = '\u00A0'; }
      }
    } catch(e) {}
    try{ body.textContent=''; }catch(e){}
    // create a single compact preformatted listing
    var combined = {};
    try { Object.keys(payloads).forEach(function(k){ combined[k] = payloads[k]; }); } catch(e) {}
    var flat = flattenObject(combined, '');
    // create a responsive compact grid of tiny key/value cards for maximum density
    var grid = document.createElement('div'); grid.className = 'diag-compact-grid';
    // put each flattened line into a tiny card: key on the left, value on the right (monospace)
    for (var i = 0; i < flat.length; i++) {
      var line = flat[i];
      var eq = line.indexOf('=');
      var key = eq >= 0 ? line.slice(0, eq) : line;
      var val = eq >= 0 ? line.slice(eq+1) : '';
      var card = document.createElement('div'); card.className = 'diag-compact-card';
      var kdiv = document.createElement('div'); kdiv.className = 'diag-compact-key'; kdiv.textContent = key;
      var vdiv = document.createElement('div'); vdiv.className = 'diag-compact-val'; vdiv.textContent = val;
      // tooltip with full value for hover
      try { card.setAttribute('title', key + ' = ' + val); } catch(e) {}
      // click to expand full JSON in modal
      (function(k, v, lineStr){ card.addEventListener('click', function(ev){ try { var pre = document.getElementById('diag-expand-pre'); if (pre) pre.textContent = JSON.stringify({key:k, value:v, raw:lineStr}, null, 2); var modal = document.getElementById('diag-expand-modal'); if (modal) { modal.setAttribute('aria-hidden','false'); modal.style.display='block'; } } catch(e){} ev.stopPropagation(); }); })(key, val, line);
      card.appendChild(kdiv); card.appendChild(vdiv);
      grid.appendChild(card);
    }
    body.appendChild(grid);
    // small snapshot line
    var meta = document.createElement('div'); meta.className='diag-small'; meta.style.marginTop='8px'; meta.textContent = 'Snapshot at: ' + new Date().toLocaleString(); body.appendChild(meta);
    // update compact footer summary too
    try {
      var parts = [];
  // omit hostname from compact footer summary (user requested)
  try { /* intentionally omitted hostname */ } catch(e){}
      try { if (payloads.summary && (payloads.summary.olsr_nodes_count || payloads.summary.olsr_nodes)) parts.push('Nodes:' + (payloads.summary.olsr_nodes_count || payloads.summary.olsr_nodes)); } catch(e){}
      try { if (payloads.summary && (payloads.summary.olsr_routes_count || payloads.summary.olsr_routes)) parts.push('Routes:' + (payloads.summary.olsr_routes_count || payloads.summary.olsr_routes)); } catch(e){}
      try { if (payloads.fetch_debug && payloads.fetch_debug.queue_length) parts.push('Q:' + payloads.fetch_debug.queue_length); } catch(e){}
      try { setFooterText('footer-diag-summary', parts.join(' • ') || '\u00A0'); } catch(e) {}
    } catch(e) {}
  }

  function fetchAllAndRender(){
    var p = {};
    // fetch versions.json, capabilities, fetch_debug, status/summary in parallel
    // Prefer the combined diagnostics endpoint if available
    fetch('/diagnostics.json', {cache:'no-store'}).then(function(r){
      if (!r || !r.ok) throw new Error('Failed to fetch diagnostics');
      return r.text();
    }).then(function(txt){
      // Try full tolerant parse first
      try {
        var j = safeParseJson(txt);
        renderDiagnostics(j); return;
      } catch(e) {}
      // salvage top-level keys (globals etc.) from noisy text
      try {
        ['globals','versions','capabilities','fetch_debug','summary'].forEach(function(k){ try { var v = extractTopLevelKey(txt, k); if (v !== null) p[k] = v; } catch(e){} });
      } catch(e){}
      // fall back to per-endpoint fetches for anything missing
      var tasks = [
        fetch('/versions.json',{cache:'no-store'}).then(r => r.text()).then(t => { try { return JSON.parse(t); } catch(e) { return {error: 'JSON parse error: ' + e.message}; } }).then(j=>p.versions=j).catch(function(e){ p.versions = {error: String(e)}; }),
        fetch('/capabilities',{cache:'no-store'}).then(r => r.text()).then(t => { try { return JSON.parse(t); } catch(e) { return {error: 'JSON parse error: ' + e.message}; } }).then(j=>p.capabilities=j).catch(function(e){ p.capabilities={error:String(e)}; }),
        fetch('/fetch_debug',{cache:'no-store'}).then(r => r.text()).then(t => { try { return JSON.parse(t); } catch(e) { return {error: 'JSON parse error: ' + e.message}; } }).then(j=>p.fetch_debug=j).catch(function(e){ p.fetch_debug={error:String(e)}; }),
        fetch('/status/summary',{cache:'no-store'}).then(r => r.text()).then(t => { try { return JSON.parse(t); } catch(e) { return {error: 'JSON parse error: ' + e.message}; } }).then(j=>p.summary=j).catch(function(e){ p.summary={error:String(e)}; })
      ];
      Promise.all(tasks).then(function(){ renderDiagnostics(p); }).catch(function(){ renderDiagnostics(p); });
    }).catch(function(){
  // diagnostics endpoint completely unavailable: fetch fallback diagnostics endpoints
      var tasks = [
        fetch('/versions.json',{cache:'no-store'}).then(r => r.text()).then(t => { try { return JSON.parse(t); } catch(e) { return {error: 'JSON parse error: ' + e.message}; } }).then(j=>p.versions=j).catch(function(e){ p.versions = {error: String(e)}; }),
        fetch('/capabilities',{cache:'no-store'}).then(r => r.text()).then(t => { try { return JSON.parse(t); } catch(e) { return {error: 'JSON parse error: ' + e.message}; } }).then(j=>p.capabilities=j).catch(function(e){ p.capabilities={error:String(e)}; }),
        fetch('/fetch_debug',{cache:'no-store'}).then(r => r.text()).then(t => { try { return JSON.parse(t); } catch(e) { return {error: 'JSON parse error: ' + e.message}; } }).then(j=>p.fetch_debug=j).catch(function(e){ p.fetch_debug={error:String(e)}; }),
        fetch('/status/summary',{cache:'no-store'}).then(r => r.text()).then(t => { try { return JSON.parse(t); } catch(e) { return {error: 'JSON parse error: ' + e.message}; } }).then(j=>p.summary=j).catch(function(e){ p.summary={error:String(e)}; })
      ];
      Promise.all(tasks).then(function(){ renderDiagnostics(p); }).catch(function(){ renderDiagnostics(p); });
    });
  }

  // wire footer click to toggle panel
  document.addEventListener('DOMContentLoaded', function(){
    var footer = el('status-footer'); if(!footer) return;
    // clickable area: entire footer should open when clicked
    footer.style.cursor='pointer'; footer.style.pointerEvents='auto';
    footer.addEventListener('click', function(e){
      var panel = el('footer-diagnostics-panel'); if(!panel) return;
      var hidden = panel.getAttribute('aria-hidden') === 'true' || !panel.getAttribute('aria-hidden');
      showDiagnostics(hidden);
      if(hidden) fetchAllAndRender();
      e.stopPropagation();
    });
    var closeBtn = el('footer-diagnostics-close'); if(closeBtn) closeBtn.addEventListener('click', function(ev){ showDiagnostics(false); ev.stopPropagation(); });
    // view toggle (Compact <-> Raw)
    var viewToggle = el('diag-view-toggle');
    if (viewToggle) {
      viewToggle.addEventListener('click', function(ev){
        var body = el('footer-diagnostics-body'); if(!body) return;
        if (viewToggle.textContent.trim() === 'Compact') { viewToggle.textContent = 'Raw'; // show raw pre
          var pre = document.createElement('pre'); pre.className='diag-compact-pre diag-raw-pre'; pre.textContent = '';
          // fetch latest diagnostics and render raw
          fetch('/diagnostics.json',{cache:'no-store'}).then(function(r){ return r.text(); }).then(function(txt){
            try { var j = safeParseJson(txt); pre.textContent = JSON.stringify(j, null, 2); } catch(e){ pre.textContent = 'Error parsing JSON: '+String(e)+'\n--- Raw response ---\n'+txt; }
          });
          clearChildren(body); body.appendChild(pre);
        } else { viewToggle.textContent = 'Compact'; fetchAllAndRender(); }
        ev.stopPropagation();
      });
    }
    var flattenBtn = el('diag-flatten-btn');
    if (flattenBtn) {
      flattenBtn.addEventListener('click', function(ev){
        var body = el('footer-diagnostics-body'); if(!body) return;
        clearChildren(body);
        var pre = document.createElement('pre'); pre.className='diag-compact-pre diag-raw-pre'; pre.textContent = 'Loading...'; body.appendChild(pre);
        fetch('/diagnostics.json',{cache:'no-store'}).then(function(r){ return r.text(); }).then(function(txt){
          var j;
          try { j = safeParseJson(txt); } catch(pe) {
            // salvage globals if present
            var salv = extractTopLevelKey(txt, 'globals');
            if (salv !== null) j = { globals: salv };
            else { var snippet = String(txt||'').slice(0,4000); pre.textContent = 'Error parsing JSON: '+String(pe)+'\n--- Response snippet ---\n'+snippet; return; }
          }
          // flatten client-side
          var out = [];
          function flatten(o, prefix){
            prefix = prefix || '';
            if (o === null) { out.push(prefix + '=null'); return; }
            if (typeof o === 'string' || typeof o === 'number' || typeof o === 'boolean') { out.push(prefix + '=' + String(o)); return; }
            if (Array.isArray(o)) { if (o.length === 0) { out.push(prefix + '=[]'); return; } for (var i=0;i<o.length;i++){ flatten(o[i], prefix + '['+i+']'); } return; }
            var keys = Object.keys(o).sort(); if (keys.length === 0) { out.push(prefix + '={}'); return; }
            for (var ki=0; ki<keys.length; ki++){ var k = keys[ki]; var p = prefix ? (prefix + '.' + k) : k; flatten(o[k], p); }
          }
          flatten(j,''); pre.textContent = out.join('\n');
        }).catch(function(e){ pre.textContent = 'Error: ' + String(e); });
        ev.stopPropagation();
      });
    }
    // modal close
    var modalClose = el('diag-expand-close'); if (modalClose) modalClose.addEventListener('click', function(ev){ var m = el('diag-expand-modal'); if (m) { m.setAttribute('aria-hidden','true'); m.style.display='none'; } ev.stopPropagation(); });
    // hide modal on overlay click
    var modalOverlay = el('diag-expand-modal'); if (modalOverlay) modalOverlay.addEventListener('click', function(ev){ if (ev.target === modalOverlay) { modalOverlay.setAttribute('aria-hidden','true'); modalOverlay.style.display='none'; } });
  });
})();

// RTT / latency measurement for footer display
(function(){
  var lastRtt = null;
  var pingPathCandidates = ['/status/ping','/status/lite'];
  function updateLatencyText(rtt){
    try{
      var el = document.getElementById('footer-latency');
      if(!el) return;
      if(typeof rtt !== 'number' || isNaN(rtt)) { el.textContent = 'RTT: -- ms'; el.className = ''; return; }
      var txt = 'RTT: ' + String(Math.round(rtt)) + ' ms';
      el.textContent = txt;
      // small heuristic thresholds
      el.className = '';
      if (rtt < 120) el.classList.add('footer-latency-ok');
      else if (rtt < 400) el.classList.add('footer-latency-warn');
      else el.classList.add('footer-latency-bad');
    }catch(e){}
  }

  function tryPingPath(idx){
    if (idx >= pingPathCandidates.length) return Promise.reject(new Error('no ping path'));
    var p = pingPathCandidates[idx];
    var t0 = Date.now();
    return fetch(p, {cache:'no-store', method:'GET'}).then(function(r){
      var t1 = Date.now();
      if (!r || !r.ok) {
        // try next candidate
        return tryPingPath(idx+1);
      }
      lastRtt = t1 - t0;
      updateLatencyText(lastRtt);
      return lastRtt;
    }).catch(function(){
      return tryPingPath(idx+1);
    });
  }

  function pingOnce(){ tryPingPath(0).catch(function(){ updateLatencyText(null); }); }

  // Start periodic ping and run once immediately after DOM ready
  document.addEventListener('DOMContentLoaded', function(){ pingOnce(); window.setInterval(pingOnce, 10000); });
})();

window.refreshTab = function(id, url) {
  var el = document.getElementById(id);
  if (el) el.textContent = 'Loading…';
  fetch(url, {cache:"no-store"}).then(function(r){
    return r.text().then(function(t){
      if (!r.ok) {
        el.textContent = "HTTP " + r.status + "\n" + t;
        return;
      }
      el.textContent = t;
    });
  }).catch(function(e){ el.textContent = "ERR: "+e; });
};

// UI debug flag (set true in console to enable debug logs)
// Default to false during normal operation to avoid verbose console output.
// You can enable diagnostics by setting `window._uiDebug = true` in the browser console.
if (typeof window._uiDebug === 'undefined') window._uiDebug = false;

// --- WebUI request logging wrapper and Diagnostics modal wiring ---
// Wrap fetch to record webui request/response for diagnostics (bounded log)
(function(){
  if (!window.fetch) return;
  var _origFetch = window.fetch;
  window._webui_request_log = window._webui_request_log || [];
  window._webui_request_log_max = 50; // keep last 50 entries
  window.fetch = function(input, init){
    var t0 = Date.now();
    var method = (init && init.method) ? init.method : 'GET';
    var url = (typeof input === 'string')? input : (input && input.url) ? input.url : String(input);
    var logEntry = { id: Date.now()+Math.random(), url: url, method: method, request_init: { headers: init && init.headers? init.headers : undefined }, start: t0 };
    return _origFetch.apply(this, arguments).then(function(resp){
      var t1 = Date.now();
      try {
        var clone = resp.clone();
        clone.text().then(function(bodyText){
          logEntry.duration_ms = t1 - t0;
          logEntry.status = resp.status;
          logEntry.response_sample = bodyText && bodyText.length>10240 ? bodyText.substring(0,10240)+'...': bodyText;
          window._webui_request_log.push(logEntry);
          while(window._webui_request_log.length>window._webui_request_log_max) window._webui_request_log.shift();
        }).catch(function() {
          logEntry.duration_ms = t1 - t0; logEntry.status = resp.status; window._webui_request_log.push(logEntry);
          while(window._webui_request_log.length>window._webui_request_log_max) window._webui_request_log.shift();
        });
      } catch(e) { try{ logEntry.duration_ms = t1 - t0; logEntry.status = resp.status; window._webui_request_log.push(logEntry); }catch(_){} }
      return resp;
    }).catch(function(err){ var t1 = Date.now(); try{ logEntry.duration_ms = t1 - t0; logEntry.error = String(err); window._webui_request_log.push(logEntry); while(window._webui_request_log.length>window._webui_request_log_max) window._webui_request_log.shift(); }catch(_){}; throw err; });
  };
})();

// Diagnostics modal wiring (opened from footer-diagnostics button)
  document.addEventListener('DOMContentLoaded', function(){
    try {
      // support both legacy id 'footer-diagnostics' and the current 'footer-diagnostics-handle'
      var diagBtn = document.getElementById('footer-diagnostics') || document.getElementById('footer-diagnostics-handle');
      var modal = document.getElementById('diagnostics-modal');
      var closeBtn = document.getElementById('diag-close');
      var content = document.getElementById('diag-content');
      // open modal when handle/button clicked
      if (diagBtn && modal && content) {
        diagBtn.addEventListener('click', function(ev){ ev.stopPropagation(); modal.style.display='block'; renderDiagPage('intervals'); });
      }
      if (closeBtn && modal) {
        closeBtn.addEventListener('click', function(ev){ ev.stopPropagation(); modal.style.display='none'; });
      }
      // wire top-nav buttons inside modal
      document.querySelectorAll('.diag-nav').forEach(function(b){ b.addEventListener('click', function(ev){ ev.stopPropagation(); var p = b.getAttribute('data-page'); renderDiagPage(p); }); });

    function renderDiagPage(page){
      try {
        content.innerHTML = '';
        if (page === 'params') {
          var h = document.createElement('div'); h.textContent = 'Parameters (runtime PlParams / env derived)'; content.appendChild(h);
          var info = document.createElement('div'); info.textContent = 'Loading server-side parameters...'; content.appendChild(info);
          // Fetch combined diagnostics payload and render selected parameter groups
          fetch('/diagnostics.json', {cache:'no-store'}).then(function(res){ return res.text(); }).then(function(txt){
            try {
              var j = JSON.parse(txt);
            } catch(e) {
              try { j = JSON.parse((txt||'').trim().split(/\n+/).pop()); } catch(_) { j = null; }
            }
            content.innerHTML = '';
            content.appendChild(h);
            if (!j) {
              var pre = document.createElement('pre'); pre.style.whiteSpace='pre-wrap'; pre.textContent = 'Failed to parse /diagnostics.json'; content.appendChild(pre); return;
            }
            function addGroup(title, obj, groupKey) {
              // helper to format interval-like values in seconds
              function formatParamValue(k, rawVal, effective) {
                try {
                  if (rawVal === null || typeof rawVal === 'undefined' || rawVal === '') {
                    // apply sensible defaults for common intervals when value missing
                    if (/fetch_auto_refresh/i.test(k)) return '60 s (default)';
                    if (/links?.*interval/i.test(k)) return '10 s (default)';
                    if (/_ms$/i.test(k)) return '0 s';
                    return String(rawVal);
                  }
                  var num = Number(rawVal);
                  if (!isNaN(num)) {
                    if (/_ms$/i.test(k) || /_ms_/i.test(k) || /_ms/i.test(k) && k.toLowerCase().indexOf('ms')>-1) {
                      // milliseconds -> seconds
                      var s = num / 1000;
                      if (s === Math.floor(s)) return String(Math.floor(s)) + ' s';
                      return String(s.toFixed(2)) + ' s';
                    }
                    if (/_s$/i.test(k) || /interval/i.test(k) || /ttl/i.test(k)) {
                      return String(num) + ' s';
                    }
                  }
                  return String(rawVal);
                } catch(e) { return String(rawVal); }
              }
              var box = document.createElement('div'); box.style.border='1px solid #eee'; box.style.padding='8px'; box.style.marginBottom='8px';
              var t = document.createElement('div'); t.style.fontWeight='700'; t.textContent = title; box.appendChild(t);
              var table = document.createElement('table'); table.className='table table-condensed'; table.style.marginTop='6px';
              var tbody = document.createElement('tbody');
              // params_meta may provide friendly labels and descriptions
              var meta = (j && j.params_meta && groupKey && j.params_meta[groupKey]) ? j.params_meta[groupKey] : null;
              Object.keys(obj).sort().forEach(function(k){
                // row contains label, value, and actions
                var tr = document.createElement('tr');
                var td1 = document.createElement('td'); td1.style.width='260px'; td1.style.fontWeight='600';
                var displayKey = k;
                var descText = '';
                var plparam = null; var envvar = null; var effective = null; var desc_key = null;
                if (meta && meta[k]) {
                  try {
                    var m = meta[k];
                    if (m.label) displayKey = m.label;
                    if (m.desc) descText = m.desc;
                    if (m.plparam) plparam = m.plparam;
                    if (m.env) envvar = m.env;
                    if (m.effective) effective = m.effective; // server may supply computed source
                    if (m.desc_key) desc_key = m.desc_key;
                  } catch(e){}
                }
                // left column: display label + small meta line
                td1.textContent = displayKey;
                var metaLine = document.createElement('div'); metaLine.style.fontSize='11px'; metaLine.style.color='#777'; metaLine.style.marginTop='4px';
                var parts = [];
                if (plparam) parts.push('PlParam: ' + plparam);
                if (envvar) parts.push('Env: ' + envvar);
                if (parts.length) metaLine.textContent = parts.join(' • ');
                td1.appendChild(metaLine);

                var td2 = document.createElement('td'); td2.style.position='relative';
                var valSpan = document.createElement('div');
                try {
                  if (typeof obj[k] === 'object') valSpan.textContent = JSON.stringify(obj[k], null, 2);
                  else valSpan.textContent = formatParamValue(k, obj[k], effective);
                } catch(e){ valSpan.textContent = formatParamValue(k, obj[k], effective); }
                td2.appendChild(valSpan);

                // action column: copy button and effective source badge
                var actions = document.createElement('div'); actions.style.display='flex'; actions.style.alignItems='center'; actions.style.gap='6px'; actions.style.marginTop='6px';
                var copyBtn = document.createElement('button'); copyBtn.className='btn btn-xs btn-default'; copyBtn.textContent='Copy'; copyBtn.title='Copy value to clipboard';
                copyBtn.addEventListener('click', function(){
                  try {
                    var text = valSpan.textContent || '';
                    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text);
                    else {
                      var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } catch(e){} document.body.removeChild(ta);
                    }
                    copyBtn.textContent = 'Copied'; setTimeout(function(){ copyBtn.textContent = 'Copy'; }, 1200);
                  } catch(e) { try{ copyBtn.textContent = 'Err'; setTimeout(function(){ copyBtn.textContent = 'Copy'; }, 1200); }catch(_){} }
                });
                actions.appendChild(copyBtn);
                if (!effective) { if (meta && meta[k] && meta[k].effective_source) effective = meta[k].effective_source; }
                if (effective) {
                  var badge = document.createElement('span'); badge.style.fontSize='11px'; badge.style.padding='2px 6px'; badge.style.borderRadius='10px'; badge.style.background='#eee'; badge.style.color='#333'; badge.textContent = String(effective);
                  actions.appendChild(badge);
                }
                td2.appendChild(actions);
                tr.appendChild(td1); tr.appendChild(td2); tbody.appendChild(tr);
                // description (i18n aware)
                var localDesc = descText || '';
                if (desc_key && window._i18n && window._i18n[desc_key]) localDesc = window._i18n[desc_key];
                if (localDesc) {
                  var trd = document.createElement('tr'); var dtd = document.createElement('td'); dtd.colSpan=2; dtd.style.fontSize='12px'; dtd.style.color='#666'; dtd.textContent = localDesc; trd.appendChild(dtd); tbody.appendChild(trd);
                }
              });
              table.appendChild(tbody); box.appendChild(table); content.appendChild(box);
            }

            // Preferred groups
            if (j.globals) addGroup('Globals', j.globals, 'globals');
            if (j.fetch_opts) addGroup('Fetch options', j.fetch_opts, 'fetch_opts');
            if (j.fetch) addGroup('Fetch queue settings', j.fetch, 'fetch');
            if (j.ubnt) addGroup('UBNT', j.ubnt, 'ubnt');
            if (j.arp) addGroup('ARP cache', j.arp, 'arp');
            if (j.coalesce) addGroup('Coalescing', j.coalesce, 'coalesce');
            if (j.debug) addGroup('Debug flags', j.debug, 'debug');

            // Show an "All parameters" section listing entries from params_meta so users can see every possible parameter
            if (j.params_meta) {
              var allBox = document.createElement('div'); allBox.style.border='1px dashed #ddd'; allBox.style.padding='8px'; allBox.style.marginTop='8px';
              var ah = document.createElement('div'); ah.style.fontWeight='700'; ah.textContent = 'All parameters (from params_meta)'; allBox.appendChild(ah);
              var at = document.createElement('table'); at.className='table table-condensed'; at.style.marginTop='6px'; var atb = document.createElement('tbody');
              var pmKeys = Object.keys(j.params_meta).sort();
              // recursive search for value by key across payload
              function findValueRecursive(obj, key) {
                if (!obj || typeof obj !== 'object') return undefined;
                if (Object.prototype.hasOwnProperty.call(obj, key)) return obj[key];
                for (var p in obj) {
                  if (!Object.prototype.hasOwnProperty.call(obj, p)) continue;
                  try {
                    var v = obj[p];
                    if (v && typeof v === 'object') {
                      var found = findValueRecursive(v, key);
                      if (typeof found !== 'undefined') return found;
                    }
                  } catch(e){}
                }
                return undefined;
              }
              pmKeys.forEach(function(k){
                var m = j.params_meta[k] || {};
                var displayKey = m.label || k;
                var rawVal = findValueRecursive(j, k);
                var tr = document.createElement('tr');
                var td1 = document.createElement('td'); td1.style.width='260px'; td1.style.fontWeight='600'; td1.textContent = displayKey;
                var td2 = document.createElement('td');
                var vdiv = document.createElement('div'); vdiv.textContent = (typeof rawVal === 'undefined') ? '(not set)' : formatParamValue(k, rawVal, m.effective || m.effective_source);
                td2.appendChild(vdiv);
                var metaLine = document.createElement('div'); metaLine.style.fontSize='11px'; metaLine.style.color='#777'; metaLine.style.marginTop='4px';
                var parts = [];
                if (m.plparam) parts.push('PlParam: ' + m.plparam);
                if (m.env) parts.push('Env: ' + m.env);
                if (parts.length) metaLine.textContent = parts.join(' • ');
                td1.appendChild(metaLine);
                tr.appendChild(td1); tr.appendChild(td2); atb.appendChild(tr);
              });
              at.appendChild(atb); allBox.appendChild(at); content.appendChild(allBox);
            }

            // fallback: dump the full diagnostics object into a collapsible panel
            var rawBox = document.createElement('div'); rawBox.style.marginTop='8px'; var rawBtn = document.createElement('button'); rawBtn.className='btn btn-xs btn-default'; rawBtn.textContent='Show full diagnostics JSON'; rawBox.appendChild(rawBtn);
            var rawPre = document.createElement('pre'); rawPre.style.whiteSpace='pre-wrap'; rawPre.style.display='none'; rawPre.textContent = JSON.stringify(j, null, 2);
            rawBtn.addEventListener('click', function(){ rawPre.style.display = rawPre.style.display === 'none' ? 'block' : 'none'; });
            content.appendChild(rawBox); content.appendChild(rawPre);
          }).catch(function(e){
            // network or parse error: show local parameters
            content.innerHTML = '';
            content.appendChild(h);
            var t = document.createElement('pre'); t.style.whiteSpace='pre-wrap'; t.textContent = JSON.stringify({ fetch_auto_refresh_ms: window._fetch_auto_refresh_ms || null, links_poll_interval_ms: window._links_poll_interval_ms || null }, null, 2);
            content.appendChild(t);
          });
        } else if (page === 'intervals') {
          var row = document.createElement('div'); row.style.display='flex'; row.style.flexDirection='column'; row.style.gap='8px';
          var lbl = document.createElement('div'); lbl.textContent='Polling intervals — change and they take effect immediately'; row.appendChild(lbl);
          function addRow(labelText, localKey, defaultVal, opts) {
            opts = opts || {};
            var wr = document.createElement('div'); wr.style.display='flex'; wr.style.alignItems='center'; wr.style.gap='8px';
            var kLbl = document.createElement('div'); kLbl.style.width='220px'; kLbl.textContent = labelText; wr.appendChild(kLbl);
            var inp = document.createElement('input'); inp.type='number'; inp.min='1'; inp.style.width='120px';
            var stored = localStorage.getItem(localKey);
            if (stored !== null) inp.value = stored; else inp.value = String(defaultVal);
            inp.addEventListener('change', function(){
              var v = parseInt(inp.value,10);
              if (isNaN(v) || v < 1) v = defaultVal;
              localStorage.setItem(localKey, String(v));
              // apply to runtime globals
              try {
                if (localKey === 'links_live_interval_s') {
                  window._links_poll_interval_ms = v * 1000;
                  if (typeof stopLinksPoll === 'function' && typeof startLinksPoll === 'function') { try{ stopLinksPoll(); startLinksPoll(); } catch(e){} }
                } else if (localKey === 'fetch_auto_refresh_ms') {
                  // this value is expected in milliseconds
                  window._fetch_auto_refresh_ms = v;
                }
              } catch(e){}
            });
            wr.appendChild(inp);
            // helper note
            var note = document.createElement('div'); note.style.color='#666'; note.style.fontSize='12px'; note.textContent = opts.note || '';
            wr.appendChild(note);
            row.appendChild(wr);
          }
          var linksDefault = Math.max(1, Math.floor((window._links_poll_interval_ms || 10000) / 1000));
          addRow('Links live interval (s)', 'links_live_interval_s', linksDefault, { note: 'seconds' });
          addRow('Status auto-refresh (ms)', 'fetch_auto_refresh_ms', window._fetch_auto_refresh_ms || 10000, { note: 'milliseconds' });
          content.appendChild(row);
        } else if (page === 'logging') {
          var tbl = document.createElement('div'); tbl.style.display='flex'; tbl.style.flexDirection='column'; tbl.style.gap='6px';
          var logs = window._webui_request_log || [];
          if (logs.length === 0) { content.appendChild(document.createTextNode('No web-request logs yet.')); return; }
          // add a small filter box
          var filter = document.createElement('input'); filter.type='text'; filter.placeholder='Filter (method, url, status)'; filter.className='form-control input-sm'; filter.style.marginBottom='6px';
          content.appendChild(filter);
          var listWrap = document.createElement('div'); listWrap.style.maxHeight='420px'; listWrap.style.overflow='auto'; listWrap.style.display='flex'; listWrap.style.flexDirection='column'; listWrap.style.gap='6px';
          function renderList(q){
            listWrap.innerHTML = '';
            var items = logs.slice().reverse();
            if (q) items = items.filter(function(l){ return JSON.stringify(l).toLowerCase().indexOf(q.toLowerCase()) !== -1; });
            items.forEach(function(l){
              var r = document.createElement('div'); r.style.border='1px solid #eee'; r.style.padding='6px'; r.style.cursor='pointer'; r.style.background='#fff';
              r.textContent = '['+ (l.status || l.error || '-') +'] ' + l.method + ' ' + l.url + ' ('+(l.duration_ms||'-')+'ms)';
              var details = document.createElement('pre'); details.style.display='none'; details.style.margin='6px 0 0 0'; details.style.padding='6px'; details.style.background='#f9f9f9'; details.style.border='1px solid #ddd'; details.style.whiteSpace='pre-wrap'; details.style.fontSize='12px';
              details.textContent = JSON.stringify(l, null, 2);
              r.addEventListener('click', function(){
                if (details.style.display === 'none') {
                  details.style.display = 'block';
                } else {
                  details.style.display = 'none';
                }
              });
              var container = document.createElement('div');
              container.appendChild(r);
              container.appendChild(details);
              listWrap.appendChild(container);
            });
          }
          filter.addEventListener('input', function(){ renderList(filter.value); });
          renderList('');
          content.appendChild(tbl); content.appendChild(listWrap);
        }
      } catch(e) { try{ content.textContent = 'Failed to render page: '+e; }catch(_){} }
    }
  } catch(e) {}
});

function setText(id, text) {
  var el = document.getElementById(id);
  if (el) {
    if (typeof el.textContent !== 'undefined') {
      el.textContent = text;
    } else if (typeof el.innerText !== 'undefined') {
      el.innerText = text;
    } else {
  // fallback: remove children and append text node
  try { while (el.firstChild) el.removeChild(el.firstChild); el.appendChild(document.createTextNode(String(text))); } catch(e) { el.textContent = String(text); }
    }
    // If we're setting the hostname, attempt to replace the literal token 'nodename'
    // with the real nodename from the cached nodedb (if available). This ensures
    // any codepath that writes the hostname benefits from enrichment.
    try {
      // Replace 'nodename' token when setting hostname or the page-level host element
      // Note: brand element 'main-host' has been repurposed to show compact IP, do not alter it here.
      if ((id === 'hostname' || id === 'main-host-page') && text && typeof text === 'string' && /\bnodename\b/.test(text)) {
        var ip = '';
        var ipEl = document.getElementById('ip');
        if (ipEl && ipEl.textContent) ip = ipEl.textContent.trim();
        if (!ip) {
          // fallback: try to extract first token from nav-host which usually starts with IP
          var nav = document.getElementById('nav-host');
          if (nav && nav.textContent) {
            var tok = nav.textContent.trim().split(/\s+/)[0];
            if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(tok)) ip = tok;
          }
        }
        if (ip && window._nodedb_cache && window._nodedb_cache[ip] && window._nodedb_cache[ip].n) {
          var real = window._nodedb_cache[ip].n;
          if (real) {
            // only replace whole-word occurrences of 'nodename'
            var newText = text.replace(/\bnodename\b/g, real);
            // write back preserving textContent/innerText/innerHTML whichever was used
            if (typeof el.textContent !== 'undefined') el.textContent = newText;
            else if (typeof el.innerText !== 'undefined') el.innerText = newText;
            else el.innerHTML = newText;
          }
        }
      }
    } catch (e) { /* ignore enrichment errors */ }
  }
}

function setHTML(id, html) {
  var el = document.getElementById(id);
  if (!el) return;
  clearChildren(el);
  try {
    // parse the provided HTML string and append nodes safely
    var parser = new DOMParser();
    var doc = parser.parseFromString(html || '', 'text/html');
    Array.prototype.slice.call(doc.body.childNodes).forEach(function(n){ el.appendChild(n.cloneNode(true)); });
  } catch(e) {
    // fallback to text
    el.textContent = String(html);
  }
}

// Robustly fetch /status/lite and parse the last top-level JSON object from the
// response text. Returns a Promise that resolves to the parsed object or
// rejects on network/error conditions.
function safeFetchStatus(fetchOptionsOrText) {
  // If caller provided a pre-fetched text (string), parse it directly and
  // avoid making a network request. Otherwise treat the argument as fetch
  // options and perform a fetch to /status/lite.
  function parseStatusText(text) {
    // Try a direct parse first
    try { return JSON.parse(text); } catch (e) {
      // Fallback: extract all complete top-level JSON objects/arrays and
      // choose the most appropriate candidate.
      function extractAllTopLevelJSON(s) {
        var out = [];
        if (!s || !s.length) return out;
        var len = s.length;
        for (var i = 0; i < len; i++) {
          var ch = s[i];
          if (ch !== '{' && ch !== '[') continue;
          var open = ch; var close = (open === '{') ? '}' : ']';
          var depth = 1;
          for (var j = i + 1; j < len; j++) {
            var cj = s[j];
            if (cj === open) depth++;
            else if (cj === close) depth--;
            if (depth === 0) {
              var cand = s.substring(i, j + 1);
              try {
                var obj = JSON.parse(cand);
                out.push(obj);
              } catch (err) {
                // ignore parse errors for this candidate
              }
              i = j; // advance outer loop past this object
              break;
            }
          }
        }
        return out;
      }

      try {
        var candidates = extractAllTopLevelJSON(String(text || ''));
        if (!candidates || candidates.length === 0) throw new Error('Invalid JSON from /status/lite');
        if (candidates.length === 1) return candidates[0];
        // Prefer a candidate that looks like the full status object
        var preferredKeys = ['hostname','devices','links','fetch_stats','ip','uptime'];
        var bestCandidate = null;
        var bestScore = 0;
        for (var k = candidates.length - 1; k >= 0; k--) {
          var c = candidates[k];
          if (c && typeof c === 'object') {
            var score = 0;
            for (var pi = 0; pi < preferredKeys.length; pi++) {
              if (typeof c[preferredKeys[pi]] !== 'undefined') score++;
            }
            if (score > bestScore) {
              bestScore = score;
              bestCandidate = c;
            }
          }
        }
        if (bestCandidate) return bestCandidate;
        // If all candidates look like device entries, wrap as devices array
        var allDevices = true;
        for (var ii = 0; ii < candidates.length; ii++) {
          var cc = candidates[ii];
          if (!cc || typeof cc !== 'object') { allDevices = false; break; }
          if (typeof cc.ipv4 === 'undefined' && typeof cc.hwaddr === 'undefined' && typeof cc.ip === 'undefined') { allDevices = false; break; }
        }
        if (allDevices) return { devices: candidates };
        // Fallback: return the last candidate
        return candidates[candidates.length - 1];
      } catch (err) {
        throw new Error('Invalid JSON from /status/lite');
      }
    }
  }

  // If a string was provided, parse immediately
  if (typeof fetchOptionsOrText === 'string') {
    return new Promise(function(resolve, reject){
      try { resolve(parseStatusText(fetchOptionsOrText)); } catch (e) { reject(e); }
    });
  }

  var fetchOptions = fetchOptionsOrText || {cache:'no-store'};
  // Perform the network fetch when no pre-fetched text is available
  return fetch('/status/lite', fetchOptions).then(function(r){
    if (!r || !r.ok) throw new Error('HTTP ' + (r && r.status));
    return r.text();
  }).then(function(text){
    return parseStatusText(text);
  });
}

// Resolve a node's human name from the loaded nodedb using an IP or CIDR.
function getNodeNameForIp(ip) {
  try {
    if (!ip) return null;
    if (!window._nodedb_cache) return null;
    function ip2int(ipstr){ return ipstr.split('.').reduce(function(acc,x){return (acc<<8)+parseInt(x,10);},0) >>>0; }
    var rip = null;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip)) rip = ip2int(ip);
    var best = null; var bestMask = -1;
    Object.keys(window._nodedb_cache).forEach(function(k){
      if (!k) return;
      var v = window._nodedb_cache[k]; if (!v) return;
      try {
        // direct key exact IP match (highest priority)
        if (k === ip) { if (v.n) { best = v.n; bestMask = 32; } return; }
        // direct object host fields matching exact IP
        if (v.h === ip || v.host === ip || v.ip === ip || v.ipv4 === ip || v.addr === ip) { if (v.n && 32 > bestMask) { best = v.n; bestMask = 32; } return; }
        // CIDR key: prefer longest-prefix match
        if (k.indexOf('/') > -1 && rip !== null) {
          var parts = k.split('/'); var net = parts[0]; var bits = parseInt(parts[1],10);
          if (!isNaN(bits)) {
            var nint = ip2int(net);
            var mask = bits===0?0: (~0 << (32-bits)) >>>0;
            if ((rip & mask) === (nint & mask)) {
              if (v.n && bits > bestMask) { best = v.n; bestMask = bits; }
            }
          }
        }
        // non-IP key: inspect stored object fields for an IP equal to `ip` and prefer exact
        if (bestMask < 32) {
          var fields = ['h','host','hostname','m','ip','ipv4','addr','address'];
          for (var fi=0; fi<fields.length; fi++) {
            var fld = fields[fi]; if (!v[fld]) continue; var val = String(v[fld]).replace(/\/.*/,'');
            if (val === ip) { if (v.n && 32 > bestMask) { best = v.n; bestMask = 32; } break; }
          }
        }
      } catch(e) { /* ignore entry parse errors */ }
    });
    return best || null;
  } catch(e) { return null; }
}

/* Modal helpers: manage aria-hidden and visibility centrally */
function showModal(id) {
  var m = document.getElementById(id);
  if (!m) return;
  try { m.setAttribute('aria-hidden','false'); } catch(e) {}
  try { m.style.display = ''; } catch(e) {}
}
function hideModal(id) {
  var m = document.getElementById(id);
  if (!m) return;
  try { m.setAttribute('aria-hidden','true'); } catch(e) {}
  try { m.style.display = 'none'; } catch(e) {}
}

// Modal keyboard handling: Esc to close and focus trap within modal-panel
window._modalKeyHandler = null;

// Tab status indicator functions
function updateTabStatus(tabId, status) {
  var statusEl = document.getElementById(tabId + '-status');
  if (statusEl) {
    statusEl.className = 'tab-status ' + status;
    if (status === 'loaded') {
      statusEl.textContent = '✓';
    } else if (status === 'loading') {
      statusEl.textContent = '⟳';
    } else if (status === 'error') {
      statusEl.textContent = '✗';
    }
  }
}

function setTabLoading(tabId) {
  updateTabStatus(tabId, 'loading');
}

function setTabLoaded(tabId) {
  updateTabStatus(tabId, 'loaded');
}

function setTabError(tabId) {
  updateTabStatus(tabId, 'error');
}

function showTab(tabId, show) {
  var el = document.getElementById(tabId);
  if (!el) return;

  // Find the corresponding nav link
    var navLink = document.querySelector('#mainTabs a[href="#' + tabId + '"]');
  if (navLink) {
    var navItem = navLink.parentElement;
    if (show) {
      navItem.style.display = '';
      el.style.display = 'block';
      el.classList.remove('hidden');
    } else {
      navItem.style.display = 'none';
      el.style.display = 'none';
      el.classList.add('hidden');
    }
  }

  // diagnostics: log current state for debugging empty-tab issue
  try {
    if (window._uiDebug) console.debug('showTab called for', tabId, 'show=', !!show, 'el.style.display=', el.style.display);
  } catch(e){}
}

function populateDevicesTable(devices, airos) {
  var tbody = document.querySelector('#devicesTable tbody');
  // diagnostics: lightweight logging to help trace empty tabs issue
  try { if (window._uiDebug) console.debug('populateDevicesTable called, devices=', (devices && devices.length) || 0, 'tbodyExists=', !!tbody, 'tbodyClass=', tbody?tbody.className:'-'); } catch(e) {}
  clearChildren(tbody);
    // Ensure parent pane is not accidentally hidden (help with intermittent empty-tab issue)
    try { var pane = document.getElementById('tab-status'); if (pane) { pane.classList.remove('hidden'); pane.style.display = ''; } } catch(e) {}
  // Note: we no longer filter out ARP-like entries here. Instead compute a
  // `source` field per device and render it in the new Source column so users
  // can distinguish devices originating from ubnt-discover vs ARP vs unknown.
  // Determine a single-entry source tag for an incoming device object.
  // Returns 'ubnt-discover', 'arp' or 'unknown' for a single raw record.
  function detectSource(dev) {
    if (!dev) return 'unknown';
    try {
      var hasProduct = (dev.product || '').toString().trim().length > 0;
      var hasHostname = (dev.hostname || '').toString().trim().length > 0;
      var hasExtras = (dev.essid || dev.firmware || dev.uptime || dev.mode || dev.signal);
      if (hasProduct || hasHostname) return 'ubnt-discover';
      if (dev.hwaddr && !hasExtras && !hasProduct && !hasHostname) return 'arp';
    } catch(e) {}
    return 'unknown';
  }

  // If incoming devices is empty but we have a cached view, keep showing the cached devices
  if (!devices || !Array.isArray(devices) || devices.length === 0) {
    try { if (window._devices_data && Array.isArray(window._devices_data) && window._devices_data.length > 0) { devices = window._devices_data.slice(); } } catch(e) {}
  }
  if (!devices || !Array.isArray(devices) || devices.length === 0) {
    var tbody = document.querySelector('#devicesTable tbody');
    if (tbody) {
      clearChildren(tbody);
      var tr = document.createElement('tr');
      var tdNo = document.createElement('td'); tdNo.colSpan = 12; tdNo.className = 'text-muted'; tdNo.textContent = 'No devices found';
      tr.appendChild(tdNo); tbody.appendChild(tr);
    }
    return;
  }
  // Ensure we expose a source and wireless property on each device so sorting
  // and display works consistently.
  var warn_frequency = 0;

  // Merge duplicates and aggregate by hostname so devices with the same
  // hostname appear as a single row and list all known IPs in the Local (IP / HW)
  // column. Fallback key order: hostname, hwaddr, ipv4/ip, anon.
  try {
    var byHost = Object.create(null);
    devices.forEach(function(dev) {
      var hostKey = (dev.hostname || '').toString().trim();
      var fallbackKey = null;
      if (!hostKey) {
        if (dev.hwaddr) fallbackKey = 'hw:' + String(dev.hwaddr).toLowerCase();
        else if (dev.ipv4) fallbackKey = 'ip:' + String(dev.ipv4);
        else if (dev.ip) fallbackKey = 'ip:' + String(dev.ip);
        else fallbackKey = 'anon:' + (Math.random().toString(36).slice(2,8));
      }
      var key = hostKey || fallbackKey;

      if (!byHost[key]) {
        var copy = {};
        for (var k in dev) if (dev.hasOwnProperty(k)) copy[k] = dev[k];
        copy._ips = new Set();
        var ipVal = dev.ipv4 || dev.ip || '';
        if (ipVal) copy._ips.add(String(ipVal));
        copy._hw = new Set(); if (dev.hwaddr) copy._hw.add(String(dev.hwaddr));
        copy._sources = new Set(); copy._sources.add(detectSource(dev));
        byHost[key] = copy;
      } else {
        var cur = byHost[key];
        // collect IPs and hwaddrs
        var ipVal = dev.ipv4 || dev.ip || '';
        if (ipVal) cur._ips.add(String(ipVal));
        if (dev.hwaddr) cur._hw.add(String(dev.hwaddr));
        cur._sources.add(detectSource(dev));
        // prefer non-empty values for other display fields
        ['hostname','product','uptime','mode','essid','firmware','signal','tx_rate','rx_rate'].forEach(function(f){
          try { if ((!cur[f] || String(cur[f]).trim() === '') && dev[f] && String(dev[f]).trim() !== '') cur[f] = dev[f]; } catch(e) {}
        });
      }
    });

    // rebuild devices array: for each host aggregate IPs into a comma-separated string
    var mergedDevices = [];
    Object.keys(byHost).forEach(function(k){
      var item = byHost[k];
      try {
        var srcs = Array.from(item._sources).sort().filter(function(x){return x && x!=='unknown';}).join(', ');
        item.source = srcs || 'unknown';
      } catch(e){ item.source = 'unknown'; }
      // build combined ipv4 string containing all distinct IPs (comma+space)
      try { item.ipv4 = Array.from(item._ips).join(', '); } catch(e) { item.ipv4 = item.ipv4 || ''; }
      // preserve primary hwaddr if available, otherwise show first
      try { item.hwaddr = Array.from(item._hw).join(', '); } catch(e) { item.hwaddr = item.hwaddr || ''; }
      delete item._ips; delete item._hw; delete item._sources;
      mergedDevices.push(item);
    });
    devices = mergedDevices;
  } catch(e) { /* if merging fails, fall back to original devices array */ }

  // Display all devices provided by the backend (e.g. ubnt discover output)
  devices.forEach(function(device) {
    var tr = document.createElement('tr');
  // use global td(val, allowHtml) helper
  // Local IP with HW Address (smaller font) - build DOM safely
  var localIpTd = document.createElement('td');
  var localWrap = document.createElement('div'); localWrap.style.fontSize = '60%';
  var ipSpan = document.createElement('div'); ipSpan.textContent = device.ipv4 || '';
  var hwSpan = document.createElement('div'); hwSpan.textContent = device.hwaddr || '';
  localWrap.appendChild(ipSpan); localWrap.appendChild(hwSpan); localIpTd.appendChild(localWrap);
    tr.appendChild(localIpTd);
    tr.appendChild(td(device.hostname));
    tr.appendChild(td(device.product));
    tr.appendChild(td(device.uptime));
    tr.appendChild(td(device.mode));
    tr.appendChild(td(device.essid));
    // attempt to populate missing signal/tx/rx fields from airos data when available
    try {
      if (airos && device && (!device.signal || String(device.signal).trim() === '' || !device.tx_rate || String(device.tx_rate).trim() === '' || !device.rx_rate || String(device.rx_rate).trim() === '')) {
        var a = airos[device.ipv4];
        if (a && Array.isArray(a.connections) && a.connections.length > 0) {
          // try to find a matching station by MAC or hostname
          var match = null;
          var devHw = (device.hwaddr || '').toLowerCase();
          var devName = (device.hostname || '').toString();
          for (var si = 0; si < a.connections.length; si++) {
            var s = a.connections[si];
            try {
              if (s.mac && devHw && s.mac.toLowerCase() === devHw) { match = s; break; }
              if (s.name && devName && s.name === devName) { match = s; break; }
            } catch(e){}
          }
          if (!match && a.connections.length === 1) match = a.connections[0];
          if (match) {
            try { if ((!device.signal || String(device.signal).trim()==='') && typeof match.signal !== 'undefined') device.signal = String(match.signal); } catch(e){}
            try { if ((!device.tx_rate || String(device.tx_rate).trim()==='') && typeof match.tx !== 'undefined') device.tx_rate = String(match.tx); } catch(e){}
            try { if ((!device.rx_rate || String(device.rx_rate).trim()==='') && typeof match.rx !== 'undefined') device.rx_rate = String(match.rx); } catch(e){}
          }
        }
      }
    } catch(e) {}

    tr.appendChild(td(device.firmware));
    tr.appendChild(td(device.signal || ''));
    tr.appendChild(td(device.tx_rate || ''));
    tr.appendChild(td(device.rx_rate || ''));
    var wireless = '';
    var freq_start = null, freq_end = null, frequency = null, chanbw = null;
    if (airos && airos[device.ipv4] && airos[device.ipv4].wireless) {
      var w = airos[device.ipv4].wireless;
      frequency = parseInt((w.frequency || '').replace('MHz','').trim());
      chanbw = parseInt(w.chanbw || 0);
      if (frequency && chanbw) {
        freq_start = frequency - (chanbw/2);
        freq_end = frequency + (chanbw/2);
        if (freq_start < 5490 && freq_end > 5710) warn_frequency = 1;
      }
      wireless = (w.frequency ? w.frequency + 'MHz ' : '') + (w.mode || '');
    }
  // persist wireless string on device for sorting
  device.wireless = wireless;
  // compute and persist source for display/sorting
  // If merging ran above it already set device.source; otherwise detect from single record
  if (!device.source) {
    try { device.source = detectSource(device); } catch(e) { device.source = 'unknown'; }
  }
  tr.appendChild(td(wireless));
  // create Source cell with colored dot + label (for visual clarity)
  var srcTd = document.createElement('td');
  var srcWrap = document.createElement('span');
  // sanitize source string into a safe class name (comma/space -> single hyphen, remove other chars)
  var scls = 'device-source src-' + (device.source ? device.source.toLowerCase().replace(/[^a-z0-9]+/gi,'-').replace(/-+/g,'-').replace(/^-|-$/g,'') : 'unknown');
  srcWrap.className = scls;
  var dot = document.createElement('span'); dot.className = 'dot';
  var lbl = document.createElement('span'); lbl.className = 'lbl small'; lbl.innerText = device.source || 'unknown';
  srcWrap.appendChild(dot); srcWrap.appendChild(lbl); srcTd.appendChild(srcWrap); tr.appendChild(srcTd);
  tbody.appendChild(tr);
  });
  var table = document.getElementById('devicesTable');
  if (warn_frequency && table) {
    var warn = document.createElement('div');
    warn.className = 'alert alert-warning';
    warn.textContent = 'Warnung: Frequenzüberlappung erkannt!';
    table.parentNode.insertBefore(warn, table);
  }
  // attach header sort clicks to sort the provided devices array and re-render
  try {
    var headers = document.querySelectorAll('#devicesTable thead th');
    headers.forEach(function(h, idx){
      // Allow clicking headers to sort by inferred keys (map index to property)
      h.style.cursor = 'pointer';
      h.onclick = function(){
        var key = null;
        switch(idx) {
          case 0: key = 'ipv4'; break;
          case 1: key = 'hostname'; break;
          case 2: key = 'product'; break;
          case 3: key = 'uptime'; break;
          case 4: key = 'mode'; break;
          case 5: key = 'essid'; break;
          case 6: key = 'firmware'; break;
          case 7: key = 'signal'; break;
          case 8: key = 'tx_rate'; break;
          case 9: key = 'rx_rate'; break;
    case 10: key = 'wireless'; break;
    case 11: key = 'source'; break;
        }
        if (!key) return;
        if (_devicesSort.key === key) _devicesSort.asc = !_devicesSort.asc; else { _devicesSort.key = key; _devicesSort.asc = true; }
        try {
          var arr = window._devices_data = window._devices_data || devices.slice();
          arr.sort(function(a,b){
            var ka = a[_devicesSort.key]; var kb = b[_devicesSort.key];
            // numeric-aware fields
            if (_devicesSort.key === 'signal' || _devicesSort.key === 'tx_rate' || _devicesSort.key === 'rx_rate') {
              var an = parseFloat(String(ka||'').replace(/[^0-9\.\-]/g,'')); var bn = parseFloat(String(kb||'').replace(/[^0-9\.\-]/g,''));
              if (!isNaN(an) && !isNaN(bn)) return _devicesSort.asc ? (an - bn) : (bn - an);
            }
            ka = String(ka||'').toLowerCase(); kb = String(kb||'').toLowerCase(); if (ka < kb) return _devicesSort.asc?-1:1; if (ka>kb) return _devicesSort.asc?1:-1; return 0;
          });
          populateDevicesTable(arr, airos);
        } catch(e) { populateDevicesTable(devices, airos); }
      };
    });
  } catch(e){}
}

function populateOlsrLinksTable(links) {
  var tbody = document.querySelector('#olsrLinksTable tbody');
  if (!tbody) return; clearChildren(tbody);
  // If we don't have a loaded nodedb cache yet, fetch it first so name
  // resolution can prefer canonical node names (same behavior as Connections tab).
  // Avoid repeated fetches by using a fetching flag. After load, re-run this
  // function to populate the table with enriched names.
  try {
    if (!window._nodedb_cache && !window._nodedb_fetching) {
      window._nodedb_fetching = true;
      fetch('/nodedb.json', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(nb){
        try { window._nodedb_cache = nb || {}; } catch(e) { window._nodedb_cache = {}; }
        window._nodedb_fetching = false;
        try { populateOlsrLinksTable(links); } catch(e) {}
      }).catch(function(){ window._nodedb_fetching = false; try { populateOlsrLinksTable(links); } catch(e) {} });
      // Defer actual rendering until we have attempted to fetch nodedb
      return;
    }
  } catch(e) {}
  // diagnostics: lightweight logging to help trace empty tabs issue
  try { if (window._uiDebug) console.debug('populateOlsrLinksTable called, links=', (links && links.length) || 0, 'tbodyExists=', !!tbody, 'tbodyClass=', tbody?tbody.className:'-'); } catch(e) {}
  if (!links || !Array.isArray(links) || links.length === 0) {
    var tbody = document.querySelector('#olsrLinksTable tbody');
    if (tbody) {
  clearChildren(tbody);
      var tr = document.createElement('tr');
      var tdNo = document.createElement('td'); tdNo.colSpan = 12; tdNo.className = 'text-muted'; tdNo.textContent = 'No links found';
      tr.appendChild(tdNo); tbody.appendChild(tr);
    }
    return;
  }
  // always refresh cached links to reflect latest server data
  try { window._olsr_links = Array.isArray(links) ? links.slice() : (links || []); } catch(e) { window._olsr_links = links || []; }
  links.forEach(function(l){
    var tr = document.createElement('tr');
    if (l.is_default) { tr.style.backgroundColor = '#fff8d5'; }
  // use global td(val, allowHtml) helper
    tr.appendChild(td(l.intf));
    tr.appendChild(td(l.local));
    tr.appendChild(td(l.remote));
    // show remote_host if available, otherwise show remote IP
    try {
      if (l.remote_host && String(l.remote_host).trim()) {
        var linkHtml = '<a target="_blank" href="https://' + l.remote_host + '">' + l.remote_host + '</a>';
        try {
          var tmpTd = document.createElement('td');
          var p = new DOMParser(); var doc = p.parseFromString(linkHtml || '', 'text/html');
          Array.prototype.slice.call(doc.body.childNodes).forEach(function(n){ tmpTd.appendChild(n.cloneNode(true)); });
          tr.appendChild(tmpTd);
        } catch(e) { tr.appendChild(td(l.remote_host)); }
      } else {
        tr.appendChild(td(l.remote));
      }
    } catch(e){ tr.appendChild(td(l.remote_host || l.remote)); }
  // Resolve node name with multiple heuristics and return reason for diagnostics
  function resolveNodeNameForLink(link) {
    var remote = link && link.remote ? String(link.remote) : '';
    var parts = [];
    if (link.node_names && typeof link.node_names === 'string') parts = link.node_names.split(',').map(function(s){ return s.trim(); }).filter(function(x){ return x.length; });
    var resolved = null; var reason = 'none';

    // 1) Try resolving by IP/CIDR via nodedb first (most authoritative) - use same logic as Connections tab
    if (typeof getNodeNameForIp === 'function') {
      try { var nn = getNodeNameForIp(remote); if (nn) { resolved = nn; reason = 'nodedb-cidr-or-key'; } } catch(e){}
    }

    // 1b) If getNodeNameForIp didn't work, try direct nodedb lookup using same logic as Connections tab
    if (!resolved && window._nodedb_cache) {
      // Check if remote IP is a direct key in nodedb cache
      var entry = window._nodedb_cache[remote];
      if (entry && entry.n) {
        resolved = entry.n;
        reason = 'nodedb-direct-key';
      } else {
        // Check other nodedb entries where this IP might be referenced in h, host, ip, ipv4, addr fields
        Object.keys(window._nodedb_cache).some(function(k){
          var v = window._nodedb_cache[k];
          if (!v) return false;
          try {
            // Check if this entry references the remote IP via various host fields
            if (v.h === remote || v.host === remote || v.ip === remote || v.ipv4 === remote || v.addr === remote) {
              if (v.n) {
                resolved = v.n;
                reason = 'nodedb-host-field-match';
                return true;
              }
            }
          } catch(e){}
          return false;
        });
      }
    }

    // 2) Prefer explicit node_names that exactly match nodedb entries mapped to this remote
    if (!resolved && parts.length && window._nodedb_cache) {
      for (var i=0;i<parts.length;i++) {
        var pname = parts[i];
        var found = false;
        Object.keys(window._nodedb_cache).some(function(k){
          var v = window._nodedb_cache[k]; if(!v) return false;
          try {
            // If the nodedb entry's canonical name matches the node_names part, accept it.
            // Previously we required additional equality checks against the remote IP or host
            // fields which made matches fail for CIDR keys or when entries used different
            // address representations. Accepting v.n === pname gives better coverage while
            // remaining conservative because nodedb canonical names are usually unique.
            if (v.n === pname) { found = true; return true; }
            // fallback: if this nodedb entry explicitly references the remote IP via
            // host/mask/m fields, consider it a match as well.
            if (k === remote || v.h === remote || v.m === remote) { if (v.n === pname) { found = true; return true; } }
            try { if (typeof getNodeNameForIp === 'function' && getNodeNameForIp(remote) === pname) { found = true; return true; } } catch(e) {}
          } catch(e){}
          return false;
        });
        if (found) { resolved = pname; reason = 'node_names->nodedb-match'; break; }
      }
    }

    // 3) Check for explicit link fields that often carry node names
    if (!resolved) {
      var altFields = ['remote_node','remote_node_name','remote_name','node','node_name','name'];
      for (var af=0; af<altFields.length; af++) {
        var fld = altFields[af]; if (link[fld]) { resolved = link[fld]; reason = 'alt-field-'+fld; break; }
      }
    }

    // 4) If still not resolved, prefer first node_names entry
    if (!resolved && parts.length) {
      // Avoid selecting short device-like names (e.g. 'eno', 'eth0') when a
      // canonical node name can be obtained from nodedb for this remote IP.
      try {
        var firstPart = parts[0];
        if (firstPart && firstPart.length <= 4) {
          try {
            if (typeof getNodeNameForIp === 'function') {
              var alt = getNodeNameForIp(remote);
              if (alt) { resolved = alt; reason = 'nodedb-prefer-over-short-node_names'; }
            }
          } catch(e) {}
        }
      } catch(e){}
      if (!resolved) { resolved = parts[0]; reason = 'first-node_names-fallback'; }
    }

    // 5) Prefer remote_host if available
    if (!resolved && link.remote_host) { resolved = link.remote_host; reason = 'remote_host-fallback'; }

    // 6) final fallback: remote IP string
    if (!resolved) { resolved = remote; reason = 'ip-fallback'; }
    return { name: resolved, reason: reason, parts: parts };
  }
  var rn = resolveNodeNameForLink(l);
  var primary = rn.name || '';
  // Attach diagnostic tooltip when UI debug enabled
  try { if (window._uiDebug && rn) console.debug('OLSR link node resolution', { remote: l.remote, node_names: l.node_names, resolved: rn.name, reason: rn.reason, parts: rn.parts }); } catch(e) {}
  var nodeTd = td(primary);
  if (l.node_names) { nodeTd.title = l.node_names; }
  tr.appendChild(nodeTd);
    // LQ / NLQ as numeric badges
    // LQ / NLQ as numeric badges
    // Treat values >= 1.0 as good (green). Values below 1.0 become progressively more red.
    function mkLqBadge(val){
      var v = parseFloat(String(val||'')||'0');
      var cls = 'lq-high'; // default: bad (red)
      if (!isFinite(v) || v <= 0) {
        cls = 'lq-high';
      } else if (v >= 1.0) {
        cls = 'lq-low'; // green
      } else if (v >= 0.85) {
        cls = 'lq-med'; // amber
      } else {
        cls = 'lq-high'; // red
      }
      return '<span class="lq-badge '+cls+'">'+String(val)+'</span>';
    }
    tr.appendChild(td(mkLqBadge(l.lq)));
    try {
      // Create a single TD that contains the NLQ badge. Previously we
      // accidentally nested a TD inside another TD which duplicated the
      // rendered content and broke table semantics.
      var nlqCell = td(mkLqBadge(l.nlq));
      tr.appendChild(nlqCell);
    } catch(e) { tr.appendChild(td(mkLqBadge(l.nlq))); }
    // cost numeric rendering
    var costVal = l.cost || '';
    var costNum = parseFloat(String(costVal).replace(/[^0-9\.\-]/g,''));
    var costHtml = '<span class="metric-badge small" style="background:#888;">'+(costVal||'')+'</span>';
    if (!isNaN(costNum)) {
      costHtml = '<span class="metric-badge small" style="background:#5a9bd8;">'+costNum+'</span>';
    }
    try {
      var costTd = document.createElement('td');
      var costSpan = document.createElement('span'); costSpan.className = 'metric-badge small'; costSpan.style.background = (!isNaN(costNum) ? '#5a9bd8' : '#888');
      costSpan.textContent = (isNaN(costNum) ? (costVal||'') : costNum);
      costTd.appendChild(costSpan); tr.appendChild(costTd);
    } catch(e) { tr.appendChild(td(costVal||'')); }
    // ETX rendering: prefer explicit etx field, otherwise compute from cost/lq where possible
    try {
      var etxVal = null;
      if (typeof l.etx !== 'undefined' && l.etx !== null && l.etx !== '') etxVal = parseFloat(String(l.etx).replace(/[^0-9\.\-]/g,''));
      else if (l.cost) {
        var cnum = parseFloat(String(l.cost).replace(/[^0-9\.\-]/g,''));
        if (!isNaN(cnum) && cnum > 0) {
          etxVal = (cnum > 100 ? (cnum / 1000) : cnum);
        }
      }
      var etxHtml = '';
      if (etxVal === null || !isFinite(etxVal)) {
        etxHtml = '<span class="etx-badge etx-med">n/a</span>';
      } else {
        var etxCls = (etxVal <= 1.5) ? 'etx-good' : (etxVal <= 3.0 ? 'etx-med' : 'etx-bad');
        etxHtml = '<span class="etx-badge '+etxCls+'">'+(Math.round(etxVal*100)/100) +'</span>';
      }
        try {
          var etxTd = document.createElement('td');
          var etxSpan = document.createElement('span'); etxSpan.className = 'etx-badge ' + etxCls; etxSpan.textContent = (etxVal === null || !isFinite(etxVal) ? 'n/a' : (Math.round(etxVal*100)/100));
          etxTd.appendChild(etxSpan); tr.appendChild(etxTd);
        } catch(e) { tr.appendChild(td('')); }
    } catch(e) { tr.appendChild(td('')); }
    var routesCell = td(l.routes || '');
    if (l.routes && parseInt(l.routes,10) > 0) {
      routesCell.style.cursor='pointer'; routesCell.title='Click to view routes via this neighbor';
      routesCell.addEventListener('click', function(){ showRoutesFor(l.remote); });
    }
  // Previously we appended an extra metric badge inside the Routes cell
  // (e.g. a blue bootstrap-styled pill). That duplicated the numeric value
  // visually; keep only the plain numeric/text routes value to avoid
  // duplicate rendering and conserve horizontal space.
    tr.appendChild(routesCell);
    // nodes column: show numeric count and tooltip with names (avoid duplicating long text in table)
    var nodeCount = '';
    try { nodeCount = (typeof l.nodes !== 'undefined' && l.nodes !== null) ? String(l.nodes) : ''; } catch(e) { nodeCount = ''; }
    var nodesCell = td(nodeCount);
    if (l.node_names) {
      nodesCell.title = l.node_names;
      // make nodes clickable when there are nodes
      if (parseInt(nodeCount,10) > 0) { nodesCell.style.cursor = 'pointer'; nodesCell.title = l.node_names; nodesCell.addEventListener('click', function(){ showNodesFor(l.remote, l.node_names); }); }
    }
  // metric badges (sparklines removed for stability)
  // nodes column (detailed node names + click handler)
  tr.appendChild(nodesCell);
  // Actions column
  var actTd = document.createElement('td');
  try {
    if (l.remote_host) {
      var btnOpen = document.createElement('button'); btnOpen.className = 'btn btn-xs btn-default action-open-host'; btnOpen.setAttribute('data-host', encodeURIComponent(l.remote_host)); btnOpen.title = 'Open remote host'; btnOpen.textContent = 'Open'; actTd.appendChild(btnOpen);
      actTd.appendChild(document.createTextNode(' '));
    }
    if (l.routes && parseInt(l.routes,10)>0) {
      var btnRoutes = document.createElement('button'); btnRoutes.className = 'btn btn-xs btn-primary action-show-routes'; btnRoutes.setAttribute('data-remote', encodeURIComponent(l.remote)); btnRoutes.textContent = 'Routes'; actTd.appendChild(btnRoutes);
      actTd.appendChild(document.createTextNode(' '));
    }
    if (l.nodes && parseInt(l.nodes,10)>0) {
      var btnNodes = document.createElement('button'); btnNodes.className = 'btn btn-xs btn-info action-show-nodes'; btnNodes.setAttribute('data-remote', encodeURIComponent(l.remote)); btnNodes.setAttribute('data-names', l.node_names ? encodeURIComponent(l.node_names) : ''); btnNodes.textContent = 'Nodes'; actTd.appendChild(btnNodes);
    }
  } catch(e) {
    // fallback: minimal text
    if (!actTd.childNodes.length) actTd.textContent = '';
  }
  tr.appendChild(actTd);
    tbody.appendChild(tr);
  });
  // after populating, ensure the table is visible when inside an active tab (avoid race where CSS hides it)
  try { var pane = document.getElementById('tab-olsr'); if (pane && pane.classList.contains('active')) { /* no-op but forces style recalculation in some browsers */ pane.style.display = ''; setTimeout(function(){ pane.style.display = ''; }, 10); } } catch(e) {}
  // Also proactively remove any hidden class from the OLSR pane so content is visible
  try { var pane2 = document.getElementById('tab-olsr'); if (pane2) { pane2.classList.remove('hidden'); pane2.style.display = ''; } } catch(e) {}
  // wire header sorting to re-sort the links array and re-render
  try {
    var lheaders = document.querySelectorAll('#olsrLinksTable thead th');
    lheaders.forEach(function(h, idx){
      h.style.cursor = 'pointer';
      h.onclick = function(){
        var key = null;
        switch(idx) {
          case 0: key='intf'; break;
          case 1: key='local'; break;
          case 2: key='remote'; break;
          case 3: key='remote_host'; break;
          case 4: key='remote_node'; break;
          case 5: key='lq'; break;
          case 6: key='nlq'; break;
          case 7: key='cost'; break;
          case 8: key='etx'; break;
          case 9: key='routes'; break;
          case 10: key='nodes'; break;
          case 11: key='actions'; break;
        };
        if (!key) return;
        if (_olsrSort.key === key) _olsrSort.asc = !_olsrSort.asc; else { _olsrSort.key = key; _olsrSort.asc = true; }
        // sort the cached links array and re-render
        try {
          var arr = window._olsr_links = window._olsr_links || links.slice();
          arr.sort(function(a,b){
            var ka = a[_olsrSort.key]; var kb = b[_olsrSort.key];
            // numeric compare for certain keys
          if (_olsrSort.key === 'lq' || _olsrSort.key === 'nlq' || _olsrSort.key === 'cost' || _olsrSort.key === 'routes' || _olsrSort.key === 'nodes' || _olsrSort.key === 'etx') {
              var an = parseFloat(String(ka||'').replace(/[^0-9\.\-]/g,'')); var bn = parseFloat(String(kb||'').replace(/[^0-9\.\-]/g,''));
              if (!isNaN(an) && !isNaN(bn)) return _olsrSort.asc ? (an - bn) : (bn - an);
            }
            ka = String(ka||'').toLowerCase(); kb = String(kb||'').toLowerCase(); if (ka < kb) return _olsrSort.asc?-1:1; if (ka>kb) return _olsrSort.asc?1:-1; return 0;
          });
          populateOlsrLinksTable(arr);
        } catch(e) { try{ populateOlsrLinksTable(links); } catch(_){} }
      };
    });
  } catch(e){}

  // Use event delegation on the table body for action buttons to avoid accumulating handlers
  try {
    tbody.onclick = function(e){
      var target = e.target || e.srcElement;
      // handle button or inner icon
      var btn = target.closest ? target.closest('button') : (target.nodeName==='BUTTON' ? target : null);
      if (!btn) return;
      if (btn.classList.contains('action-open-host')) {
        var h = decodeURIComponent(btn.getAttribute('data-host')||''); if (h) window.open('https://'+h, '_blank');
      } else if (btn.classList.contains('action-show-routes')) {
        var r = decodeURIComponent(btn.getAttribute('data-remote')||''); if (r) showRoutesFor(r);
      } else if (btn.classList.contains('action-show-nodes')) {
        var r = decodeURIComponent(btn.getAttribute('data-remote')||''); var names = decodeURIComponent(btn.getAttribute('data-names')||''); if (r) showNodesFor(r, names);
      }
    };
  } catch(e) {}
  // Update the links count in the status header
  try { var olcount = (links && Array.isArray(links)) ? links.length : 0; var el = document.getElementById('olsr-links-count'); if (el) el.textContent = olcount; } catch(e) {}
}

function showNodesFor(remoteIp, nodeNames) {
  var modal = document.getElementById('node-modal'); if (!modal) return;
  var bodyPre = document.getElementById('node-modal-body');
  var title = document.getElementById('node-modal-title');
  var countBadge = document.getElementById('node-modal-count');
  var tbody = document.getElementById('node-modal-tbody');
  var filterInput = document.getElementById('node-filter');
  var copyBtn = document.getElementById('node-copy');
  if (title) title.textContent = 'Nodes via ' + remoteIp;
  if (countBadge) { countBadge.style.display='none'; countBadge.textContent=''; }
  if (tbody) {
  clearChildren(tbody);
    var tr = document.createElement('tr'); var tdLoad = document.createElement('td'); tdLoad.colSpan = 6; tdLoad.className = 'text-muted'; tdLoad.textContent = 'Loading...'; tr.appendChild(tdLoad); tbody.appendChild(tr);
  }
  if (bodyPre) { bodyPre.style.display='none'; bodyPre.textContent='Loading...'; }

  // sorting state for node modal
  var _nodeSort = { key: null, asc: true };
  function renderRows(list) {
    if (!tbody) return;
    if (!list.length) {
  clearChildren(tbody);
      var tr = document.createElement('tr'); var tdNo = document.createElement('td'); tdNo.colSpan = 7; tdNo.className = 'text-muted'; tdNo.textContent = 'No nodes found'; tr.appendChild(tdNo); tbody.appendChild(tr);
      return;
    }
    var arr = list.slice();
    if (_nodeSort.key) {
      arr.sort(function(a,b){
        var ka = (a[_nodeSort.key]||'').toString().toLowerCase();
        var kb = (b[_nodeSort.key]||'').toString().toLowerCase();
        if (ka < kb) return _nodeSort.asc ? -1 : 1;
        if (ka > kb) return _nodeSort.asc ? 1 : -1;
        return 0;
      });
    }
    // build rows via DOM for safety and attach handlers directly
  clearChildren(tbody);
    for (var i=0;i<arr.length;i++) {
      (function(i){
        var n = arr[i];
        var rowId = 'node-row-' + i;
        var tr = document.createElement('tr'); tr.id = rowId;
        var tdIp = document.createElement('td'); tdIp.style.fontFamily='monospace'; tdIp.textContent = n.ip || ''; tr.appendChild(tdIp);
        var tdN = document.createElement('td'); tdN.textContent = n.n || ''; tr.appendChild(tdN);
        var tdI = document.createElement('td'); tdI.textContent = n.i || ''; tr.appendChild(tdI);
        var tdD = document.createElement('td'); tdD.textContent = n.d || ''; tr.appendChild(tdD);
        var tdH = document.createElement('td'); tdH.textContent = n.h || ''; tr.appendChild(tdH);
        var tdM = document.createElement('td'); tdM.textContent = n.m || ''; tr.appendChild(tdM);
        var tdActions = document.createElement('td');
        var btnCopy = document.createElement('button'); btnCopy.className='btn btn-xs btn-default node-copy-row'; btnCopy.setAttribute('data-idx', i); btnCopy.title='Copy row'; var ic1 = document.createElement('span'); ic1.className='glyphicon glyphicon-copy'; ic1.setAttribute('aria-hidden','true'); btnCopy.appendChild(ic1);
        var btnExp = document.createElement('button'); btnExp.className='btn btn-xs btn-default node-expand-row'; btnExp.setAttribute('data-idx', i); btnExp.title='Show details'; var ic2 = document.createElement('span'); ic2.className='glyphicon glyphicon-resize-full'; ic2.setAttribute('aria-hidden','true'); btnExp.appendChild(ic2);
        tdActions.appendChild(btnCopy); tdActions.appendChild(document.createTextNode(' ')); tdActions.appendChild(btnExp);
        tr.appendChild(tdActions);
        tbody.appendChild(tr);
        // attach handlers
        btnCopy.addEventListener('click', function(){ try{ var item = arr[i]; var txt = JSON.stringify(item); if(navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(txt); btnCopy.classList.add('btn-success'); setTimeout(function(){ btnCopy.classList.remove('btn-success'); },900);} else { var ta=document.createElement('textarea'); ta.value=txt; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);} }catch(e){} });
        btnExp.addEventListener('click', function(){ try{ var item = arr[i]; if (bodyPre) { bodyPre.style.display='block'; bodyPre.textContent = JSON.stringify(item, null, 2); bodyPre.scrollTop = 0; } var prev = document.querySelector('#node-modal-tbody tr.success'); if (prev) prev.classList.remove('success'); var row = document.getElementById('node-row-'+i); if (row) row.classList.add('success'); }catch(e){} });
      })(i);
    }
  }

  function applyFilter(list){
    var q = (filterInput && filterInput.value || '').trim().toLowerCase();
    if (!q) { renderRows(list); return; }
    var f = list.filter(function(n){
      return (n.ip && n.ip.toLowerCase().indexOf(q)>=0) || (n.n && n.n.toLowerCase().indexOf(q)>=0) || (n.d && n.d.toLowerCase().indexOf(q)>=0) || (n.h && n.h.toLowerCase().indexOf(q)>=0);
    });
    renderRows(f);
  }

  if (filterInput) filterInput.oninput = function(){ if (window._nodedb_cache_list) applyFilter(window._nodedb_cache_list); };
  if (copyBtn) copyBtn.onclick = function(){ try{ var visible = []; var rows = document.querySelectorAll('#node-modal-tbody tr'); for(var i=0;i<rows.length;i++){ visible.push(rows[i].textContent.trim()); } var txt = visible.join('\n'); if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(txt); copyBtn.classList.add('btn-success'); setTimeout(function(){ copyBtn.classList.remove('btn-success'); },900);} else { var ta=document.createElement('textarea'); ta.value=txt; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); } } catch(e){} };

  // use cached nodedb if present, otherwise fetch
  function findNodes(nodedb) {
    var list = [];
    if (!nodedb) return list;
    // nodedb may be object keyed by ip/net -> value { n,i,d,h,m }
    Object.keys(nodedb).forEach(function(k){
      var v = nodedb[k];
      // match if key equals remoteIp or if key is CIDR that contains remoteIp or if node_names hint provided and matches name
      // simple checks: exact match, prefix with '/', or host field equals remoteIp
      var match = false;
      if (k === remoteIp) match = true;
      else if (k.indexOf('/')>-1) {
        // CIDR: check remoteIp in CIDR using a simple numeric compare
        try{
          var parts = k.split('/'); var net = parts[0]; var bits = parseInt(parts[1],10);
          function ip2int(ip){ return ip.split('.').reduce(function(acc,x){return (acc<<8)+parseInt(x,10);},0) >>>0; }
          var rip = ip2int(remoteIp); var nint = ip2int(net); var mask = bits===0?0: (~0 << (32-bits)) >>>0;
          if ((rip & mask) === (nint & mask)) match = true;
        }catch(e){}
      }
      if (!match && v) {
        if (v.h && v.h === remoteIp) match = true;
        if (v.m && v.m === remoteIp) match = true;
        if (nodeNames && v.n && nodeNames.indexOf(v.n) !== -1) match = true;
      }
      if (match) {
        var entry = { ip: k, n: v.n || '', i: v.i || '', d: v.d || '', h: v.h || '', m: v.m || '' };
        list.push(entry);
      }
    });
    return list;
  }

  if (window._nodedb_cache) {
    var found = findNodes(window._nodedb_cache);
    window._nodedb_cache_list = found;
    if (countBadge) { countBadge.style.display='inline-block'; countBadge.textContent = found.length; }
    renderRows(found);
  if (bodyPre) bodyPre.textContent = JSON.stringify(found, null, 2);
  showModal('node-modal');
    // wire header sort clicks
    try {
      var headers = document.querySelectorAll('#node-modal-table thead th[data-key]');
      headers.forEach(function(h){ h.onclick = function(){ var k = h.getAttribute('data-key'); if (_nodeSort.key === k) _nodeSort.asc = !_nodeSort.asc; else { _nodeSort.key = k; _nodeSort.asc = true; } renderRows(window._nodedb_cache_list || found); }; });
    } catch(e) {}
    return;
  }

  fetch('/nodedb.json', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(nb){ try{ window._nodedb_cache = nb || {}; var found = findNodes(nb || {}); window._nodedb_cache_list = found; if (countBadge) { countBadge.style.display='inline-block'; countBadge.textContent = found.length; } renderRows(found); if (bodyPre) bodyPre.textContent = JSON.stringify(found, null, 2); showModal('node-modal'); }catch(e){ if(tbody){ clearChildren(tbody); var tr=document.createElement('tr'); var td=document.createElement('td'); td.colSpan=6; td.className='text-danger'; td.textContent='Error rendering nodes'; tr.appendChild(td); tbody.appendChild(tr);} if(bodyPre) bodyPre.textContent='Error'; showModal('node-modal'); } }).catch(function(){ if(tbody){ clearChildren(tbody); var tr=document.createElement('tr'); var td=document.createElement('td'); td.colSpan=6; td.className='text-danger'; td.textContent='Error loading nodedb.json'; tr.appendChild(td); tbody.appendChild(tr);} if(bodyPre) bodyPre.textContent='Error loading nodedb.json'; showModal('node-modal'); });
  // attach header sort clicks for fetched path as well
  try {
    var headers = document.querySelectorAll('#node-modal-table thead th[data-key]');
    headers.forEach(function(h){ h.onclick = function(){ var k = h.getAttribute('data-key'); if (_nodeSort.key === k) _nodeSort.asc = !_nodeSort.asc; else { _nodeSort.key = k; _nodeSort.asc = true; } renderRows(window._nodedb_cache_list || []); }; });
  } catch(e) {}
}

// Cache for parsed routes from status payload
var _rawRoutesCache = null;
function showRoutesFor(remoteIp) {
  var modal = document.getElementById('route-modal');
  if (!modal) return;
  var bodyPre = document.getElementById('route-modal-body');
  var title = document.getElementById('route-modal-title');
  var countBadge = document.getElementById('route-modal-count');
  var tbody = document.getElementById('route-modal-tbody');
  var filterInput = document.getElementById('route-filter');
  var copyBtn = document.getElementById('route-copy');
  if (title) title.textContent = 'Routes via ' + remoteIp;
  if (countBadge) { countBadge.style.display='none'; countBadge.textContent=''; }
  if (tbody) {
  clearChildren(tbody);
    var tr = document.createElement('tr'); var tdLoad = document.createElement('td'); tdLoad.colSpan = 4; tdLoad.className = 'text-muted'; tdLoad.textContent = 'Loading...'; tr.appendChild(tdLoad); tbody.appendChild(tr);
  }
  if (bodyPre) { bodyPre.style.display='none'; bodyPre.textContent='Loading...'; }
  var allRoutes = [];
  var _routeSort = { key: null, asc: true };
  function renderTable(arr){
    if (!tbody) return;
    if (!arr.length) {
      tbody.innerHTML = '';
      var tr = document.createElement('tr'); var tdNo = document.createElement('td'); tdNo.colSpan = 4; tdNo.className = 'text-muted'; tdNo.textContent = 'No matching routes'; tr.appendChild(tdNo); tbody.appendChild(tr);
      return;
    }
    var arr2 = arr.slice();
    if (_routeSort.key) {
      arr2.sort(function(a,b){ var ka=(a[_routeSort.key]||'').toString().toLowerCase(); var kb=(b[_routeSort.key]||'').toString().toLowerCase(); if(ka<kb) return _routeSort.asc?-1:1; if(ka>kb) return _routeSort.asc?1:-1; return 0; });
    }
    tbody.innerHTML = '';
    for (var i=0;i<arr2.length;i++) {
      var r = arr2[i];
      var rid = 'route-row-'+i;
      var tr = document.createElement('tr'); tr.id = rid; if (r.raw) tr.title = r.raw;
      var tdDest = document.createElement('td'); tdDest.style.fontFamily='monospace'; tdDest.textContent = r.destination || ''; tr.appendChild(tdDest);
      var tdDev = document.createElement('td'); tdDev.textContent = r.device || ''; tr.appendChild(tdDev);
      var tdMetric = document.createElement('td'); tdMetric.textContent = r.metric || ''; tr.appendChild(tdMetric);
      var tdRaw = document.createElement('td'); tdRaw.style.fontFamily='monospace'; tdRaw.style.color='#666'; tdRaw.textContent = r.raw || ''; tr.appendChild(tdRaw);
      tr.tabIndex = 0; tr.style.cursor = 'pointer';
      tbody.appendChild(tr);
    }
  }
  function applyFilter(){
    var q = (filterInput && filterInput.value || '').trim().toLowerCase();
    if (!q) { renderTable(allRoutes); return; }
    var f = allRoutes.filter(function(r){ return r.raw.toLowerCase().indexOf(q)>=0; });
    renderTable(f);
  }
  if (filterInput) {
    filterInput.oninput = function(){ applyFilter(); };
  }
  if (copyBtn) {
    copyBtn.onclick = function(){
      try {
        var visible = [];
        var q = (filterInput && filterInput.value || '').trim().toLowerCase();
        for (var i=0;i<allRoutes.length;i++) {
          if (!q || allRoutes[i].raw.toLowerCase().indexOf(q)>=0) visible.push(allRoutes[i].raw);
        }
        var txt = visible.join('\n');
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(txt);
          copyBtn.classList.add('btn-success');
          setTimeout(function(){ copyBtn.classList.remove('btn-success'); }, 900);
        } else {
          var ta = document.createElement('textarea'); ta.value = txt; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
        }
      } catch(e) {}
    };
  }
  // route modal header sorting wiring
  try {
    var rheaders = document.querySelectorAll('#route-modal-table thead th[data-key]');
    rheaders.forEach(function(h){ h.onclick = function(){ var k=h.getAttribute('data-key'); if(_routeSort.key===k) _routeSort.asc=!_routeSort.asc; else { _routeSort.key=k; _routeSort.asc=true; } renderTable(allRoutes); }; });
  } catch(e) {}
  // route raw-toggle removed from UI
  fetch('/olsr/routes?via=' + encodeURIComponent(remoteIp), {cache:'no-store'})
    .then(function(r){ return r.json ? r.json() : r; })
    .then(function(obj){
      var routesArr = [];
      if (Array.isArray(obj)) routesArr = obj; else if (obj && Array.isArray(obj.routes)) routesArr = obj.routes;
      // Normalize raw strings and parse into structured fields: destination, device, metric
      routesArr = routesArr.map(function(line){
        if (typeof line !== 'string') return '';
        var t = line.replace(/^"+|"+$/g,'').replace(/\\"/g,'"').trim();
        return t;
      }).filter(function(s){ return s.length; });
      allRoutes = routesArr.map(function(line){
        var parts = line.split(/\s+/).filter(function(p){ return p.length; });
        var destination = parts[0] || line;
        var device = '';
        var metric = '';
        if (parts.length === 2) {
          var maybe = parts[1];
          if (!isNaN(Number(maybe))) { metric = maybe; }
          else { device = maybe; }
        } else if (parts.length >= 3) {
          var last = parts[parts.length-1];
          if (!isNaN(Number(last))) {
            metric = last;
            device = parts.slice(1, parts.length-1).join(' ');
          } else {
            device = parts.slice(1).join(' ');
          }
        }
        return { destination: destination, device: device, metric: metric, raw: line };
      });
  if (countBadge) { countBadge.style.display='inline-block'; countBadge.textContent = (obj && typeof obj.count==='number'? obj.count : allRoutes.length); }
  renderTable(allRoutes);
      if (bodyPre) {
        var header=''; if (obj && !Array.isArray(obj) && typeof obj.count==='number') header='Via '+(obj.via||remoteIp)+' ('+obj.count+' routes)\n\n';
        bodyPre.textContent = header + routesArr.join('\n');
      }
    })
  .catch(function(){ if(tbody){ clearChildren(tbody); var tr=document.createElement('tr'); var td=document.createElement('td'); td.colSpan=4; td.className='text-danger'; td.textContent='Error loading routes'; tr.appendChild(td); tbody.appendChild(tr);} if(bodyPre) bodyPre.textContent='Error loading routes'; });
  showModal('route-modal');
}

window.addEventListener('load', function(){
  var c = document.getElementById('route-modal-close');
  if (c) c.addEventListener('click', function(){ hideModal('route-modal'); });
  var m = document.getElementById('route-modal');
  if (m) m.addEventListener('click', function(e){ if (e.target === m) hideModal('route-modal'); });

  var nc = document.getElementById('node-modal-close');
  if (nc) nc.addEventListener('click', function(){ hideModal('node-modal'); window._nodeModal_state = null; if (_nodeModalKeyHandler) { document.removeEventListener('keydown', _nodeModalKeyHandler); _nodeModalKeyHandler = null; } });
  var nm = document.getElementById('node-modal');
  if (nm) nm.addEventListener('click', function(e){ if (e.target === nm) { hideModal('node-modal'); window._nodeModal_state = null; if (_nodeModalKeyHandler) { document.removeEventListener('keydown', _nodeModalKeyHandler); _nodeModalKeyHandler = null; } } });
});

// keyboard nav state for node modal
var _nodeModalKeyHandler = null;

function populateOlsr2Tab(data) {
  var content = document.getElementById('olsr2-content');
  if (!content) return;
  
  // Clear existing content
  content.innerHTML = '';
  
  var dl = document.createElement('dl');
  dl.className = 'dl-horizontal';
  
  // OLSR2 Version
  var dt1 = document.createElement('dt');
  dt1.innerHTML = 'Olsrd2 Version <span class="glyphicon glyphicon-time" aria-hidden="true"></span>';
  var dd1 = document.createElement('dd');
  try {
    var version = data.olsr2_version && data.olsr2_version.version && data.olsr2_version.version[0];
    dd1.textContent = (version ? version.version_text || 'unknown' : 'unknown') + ' | ' + (version ? version.version_commit || 'unknown' : 'unknown');
  } catch(e) {
    dd1.textContent = 'unknown-version';
  }
  dl.appendChild(dt1);
  dl.appendChild(dd1);
  
  // OLSR2 Uptime
  var dt2 = document.createElement('dt');
  dt2.innerHTML = 'Olsrd2 Uptime <span class="glyphicon glyphicon-time" aria-hidden="true"></span>';
  var dd2 = document.createElement('dd');
  try {
    var timeData = data.olsr2_time && data.olsr2_time.time && data.olsr2_time.time[0];
    var uptime = timeData ? timeData.time_internal || 'unknown' : 'unknown';
    var uptimeStr = timeData ? timeData.time_system || 'unknown' : 'unknown';
    dd2.textContent = uptimeStr.split('.')[0] + ' | ' + uptime;
  } catch(e) {
    dd2.textContent = 'unknown-time';
  }
  dl.appendChild(dt2);
  dl.appendChild(dd2);
  
  // Originator
  var dt3 = document.createElement('dt');
  dt3.innerHTML = 'Originator <span class="glyphicon glyphicon-time" aria-hidden="true"></span>';
  var dd3 = document.createElement('dd');
  try {
    var originator = data.olsr2_originator && data.olsr2_originator.originator && data.olsr2_originator.originator[1];
    dd3.textContent = originator ? originator.originator || 'unknown' : 'unknown';
  } catch(e) {
    dd3.textContent = 'unknown-originator';
  }
  dl.appendChild(dt3);
  dl.appendChild(dd3);
  
  // IPv6 Default Route
  var dt4 = document.createElement('dt');
  dt4.innerHTML = 'IPv6 Default-Route <span class="glyphicon glyphicon-transfer" aria-hidden="true"></span>';
  var dd4 = document.createElement('dd');
  dd4.textContent = (data.def6_ip || 'i?') + ' via ' + (data.def6_dev || 'd?');
  dl.appendChild(dt4);
  dl.appendChild(dd4);
  
  // IPv6 OLSR2 Links
  var dt5 = document.createElement('dt');
  dt5.innerHTML = 'IPv6 OLSR2-Links <span class="glyphicon glyphicon-link" aria-hidden="true"></span>';
  var dd5 = document.createElement('dd');
  
  // Create table for OLSR2 links
  var table = document.createElement('table');
  table.className = 'table table-hover table-bordered table-condensed';
  var thead = document.createElement('thead');
  thead.style.backgroundColor = '#f5f5f5';
  var headerRow = document.createElement('tr');
  headerRow.innerHTML = '<td><b>Intf</b></td><td><b>Remote IPv6</b></td><td><b>Remote Hostname</b></td><td><b>Link-Status</b></td><td><b>Metric</b></td><td><b>routes</b></td><td><b>nodes</b></td>';
  thead.appendChild(headerRow);
  table.appendChild(thead);
  
  var tbody = document.createElement('tbody');
  try {
    var neighbors = data.olsr2_neighbors && data.olsr2_neighbors.link ? data.olsr2_neighbors.link : [];
    neighbors.forEach(function(link) {
      if (!link || !link.link_bindto) return;
      var tr = document.createElement('tr');
      if (link.link_bindto === data.def6_ip) {
        tr.style.backgroundColor = '#FFD700';
      }
      
      // Interface
      var td1 = document.createElement('td');
      td1.textContent = link['if'] || '';
      tr.appendChild(td1);
      
      // Remote IPv6
      var td2 = document.createElement('td');
      var remoteIp = link.neighbor_originator || '';
      var a = document.createElement('a');
      a.href = 'https://[' + remoteIp + ']';
      a.target = '_blank';
      a.textContent = remoteIp;
      td2.appendChild(a);
      tr.appendChild(td2);
      
      // Remote Hostname (simplified - would need node DNS lookup)
      var td3 = document.createElement('td');
      td3.textContent = 'unknown'; // Simplified - would need DNS lookup logic
      tr.appendChild(td3);
      
      // Link Status
      var td4 = document.createElement('td');
      td4.textContent = link.link_status || '';
      tr.appendChild(td4);
      
      // Metric
      var td5 = document.createElement('td');
      td5.innerHTML = 'In: ' + (link.domain_metric_in || '-') + '<br>Out: ' + (link.domain_metric_out || '-');
      tr.appendChild(td5);
      
      // Routes and Nodes (simplified)
      var td6 = document.createElement('td');
      td6.textContent = '0'; // Would need routing table processing
      tr.appendChild(td6);
      
      var td7 = document.createElement('td');
      td7.textContent = '0'; // Would need node processing
      tr.appendChild(td7);
      
      tbody.appendChild(tr);
    });
  } catch(e) {
    var tr = document.createElement('tr');
    var td = document.createElement('td');
    td.colSpan = 7;
    td.textContent = 'Error loading OLSR2 neighbors: ' + e.message;
    tr.appendChild(td);
    tbody.appendChild(tr);
  }
  
  table.appendChild(tbody);
  dd5.appendChild(table);
  dl.appendChild(dt5);
  dl.appendChild(dd5);
  
  content.appendChild(dl);
}

function updateUI(data) {
  try {
  // Prefer resolved nodename from nodedb when available
  var resolved = null;
  try { resolved = getNodeNameForIp(data.ipv4 || data.ip || ''); } catch(e) { resolved = null; }
  setText('hostname', (resolved || data.hostname) || 'Unknown');
  setText('ip', data.ip || '');
  // compact status card fields
  try { var hip = document.getElementById('status-host-ip'); if (hip) hip.textContent = data.ip || ''; } catch(e){}
  try { var hn = document.getElementById('status-hostname'); if (hn) hn.textContent = (resolved || data.hostname) || ''; } catch(e){}
  // prefer human-friendly uptime string if provided by backend
  setText('uptime', data.uptime_linux || data.uptime_str || data.uptime || '');
  setText('dl-uptime', data.uptime_linux || data.uptime_str || data.uptime || '');
  // Extract load average from uptime_linux for CPU stats
  try {
    var uptimeStr = data.uptime_linux || '';
    var loadMatch = uptimeStr.match(/load average:\s*([0-9.]+),/);
    if (loadMatch && loadMatch[1]) {
      var loadAvg = parseFloat(loadMatch[1]);
      if (!isNaN(loadAvg)) {
        pushStat('cpu_load', loadAvg);
      }
    }
  } catch(e) {}
  try { if (data.hostname) document.title = data.hostname; } catch(e) {}
  try { setText('main-host', data.ip || ''); } catch(e) {}
  try {
    // Build FQDN explicitly from backend fields. Prefer explicit node identifiers
    // (data.node, data.nodename, data.node_name, data.net) and fall back to a
    // hint from data.versions.host. If the node hint is missing or equals the
    // literal token 'nodename', attempt to substitute the real nodename from the
    // cached nodedb using the node's IP (data.ipv4 or data.ip).
    var shortHost = data.hostname || '';
    var nodeHint = data.node || data.nodename || data.node_name || data.net || '';
    if (!nodeHint && data.versions && data.versions.host) {
      try { nodeHint = String(data.versions.host).split('.')[0] || nodeHint; } catch(_) {}
    }
    var ipKey = data.ipv4 || data.ip || '';
    var nodePart = nodeHint || '';
    try {
      if ((!nodePart || nodePart === 'nodename') && ipKey && window._nodedb_cache && window._nodedb_cache[ipKey] && window._nodedb_cache[ipKey].n) {
        nodePart = window._nodedb_cache[ipKey].n;
      }
    } catch(e) { /* ignore */ }
    // Don't use 'nodename' as placeholder - use empty string if no real nodename
    if (!nodePart || nodePart === 'nodename') nodePart = '';
    var fqdn = '';
    if (shortHost) {
      if (nodePart && (nodePart.indexOf('wien.funkfeuer') !== -1 || nodePart.indexOf('.') !== -1)) {
        fqdn = shortHost + '.' + nodePart;
      } else if (nodePart) {
        fqdn = shortHost + '.' + nodePart + '.wien.funkfeuer.at';
      } else {
        fqdn = shortHost;
      }
    } else {
      fqdn = shortHost;
    }
    populateNavHost(fqdn, ipKey);
  // main-host-page is now handled by populateNavHost
  } catch(e) {}
  // render default route if available (hostname link + ip link + device)
  try {
    if (data.default_route && (data.default_route.ip || data.default_route.dev || data.default_route.hostname)) {
      var host = data.default_route.hostname || '';
      var ip = data.default_route.ip || '';
      var dev = data.default_route.dev || '';
      var parts = [];
      if (host) parts.push('<a target="_blank" href="https://' + host + '">' + host + '</a>');
      if (ip) parts.push('(<a target="_blank" href="https://' + ip + '">' + ip + '</a>)');
      var html = parts.join(' ');
      if (dev) html += ' via ' + dev;
      setHTML('default-route', html);
      setHTML('dl-default-route', html);
    } else {
      setText('default-route', 'n/a');
    }
  } catch(e) { setText('default-route', 'n/a'); }
  // Render lightweight devices if present, but fetch full device inventory
  // asynchronously from /devices.json so /status/lite stays fast.
  populateDevicesTable(data.devices, data.airos);
  try { window._devices_data = Array.isArray(data.devices) ? data.devices : []; } catch(e) { window._devices_data = []; }
  // Show loading row while fetching the full table
  try {
    var tbody = document.querySelector('#devicesTable tbody');
    if (tbody) {
      tbody.innerHTML = '';
      var tr = document.createElement('tr'); tr.id = 'devices-loading';
      var tdLoad = document.createElement('td'); tdLoad.colSpan = 12; tdLoad.className = 'text-muted'; tdLoad.textContent = 'Loading devices…';
      tr.appendChild(tdLoad); tbody.appendChild(tr);
    }
    fetch('/devices.json', {cache: 'no-store'}).then(function(r){ if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); }).then(function(d){ try { if (d && Array.isArray(d.devices)) populateDevicesTable(d.devices, d.airos || {}); } catch(e){} }).catch(function(){ try { if (window._devices_data && Array.isArray(window._devices_data)) populateDevicesTable(window._devices_data, data.airos); } catch(e){} }).finally(function(){ var el = document.getElementById('devices-loading'); if (el) el.parentNode.removeChild(el); });
  } catch(e){}
  if (data.olsr2_on) {
    showTab('tab-olsr2', true);
  } else {
    showTab('tab-olsr2', false);
  }
  try { var olcount = (data.links && Array.isArray(data.links)) ? data.links.length : (window._olsr_links? window._olsr_links.length : 0); var el = document.getElementById('olsr-links-count'); if (el) el.textContent = olcount; } catch(e) {}
  try { var su = document.getElementById('status-uptime'); if (su) su.textContent = data.uptime_linux || data.uptime_str || data.uptime || ''; } catch(e) {}
  // populate status tab versions string if present in status payload
  try {
    var sEl = document.getElementById('status-versions-string');
    if (sEl) {
      var sv = null;
      try { if (data && data.versions && data.versions.versions_string) sv = data.versions.versions_string; } catch(e){}
      if (!sv) try { if (data && data.versions_string) sv = data.versions_string; } catch(e){}
      sEl.textContent = sv ? String(sv) : '\u00A0';
    }
  } catch(e) {}
  // legacy OLSR tab visibility (if backend set olsrd_on or provided links while not olsr2)
  try {
    // Show OLSR tab whenever links are present or olsrd is running.
    // Keep tab visible if it was previously loaded to avoid UI flicker on intermittent empty payloads.
    var linkTab = document.querySelector('#mainTabs a[href="#tab-olsr"]');
    if (linkTab) {
      var currentlyVisible = linkTab.parentElement.style.display !== 'none';
      var shouldShow = (data && (data.olsrd_on || (data.links && data.links.length))) || currentlyVisible;
      if (shouldShow) {
        if (window._uiDebug) console.debug('Showing OLSR tab via updateUI: olsr2_on=', data.olsr2_on, 'olsrd_on=', data.olsrd_on, 'links_len=', (data.links && data.links.length));
        linkTab.parentElement.style.display = '';
      } else {
        linkTab.parentElement.style.display = 'none';
      }
    }
  } catch(e){}
  if (data.admin && data.admin.url) {
    showTab('tab-admin', true);
    var adminLink = document.getElementById('adminLink');
    if (adminLink) { adminLink.href = data.admin.url; adminLink.textContent = 'Login'; }
  } else {
    showTab('tab-admin', false);
  }
  } catch(e) {}
  try { setLastUpdated(); } catch(e) {}
}

// --- Modern Statistics Dashboard with Chart.js ---
window._stats_series = window._stats_series || { 
  olsr_routes: [], 
  olsr_nodes: [], 
  fetch_queued: [], 
  fetch_processing: [],
  cpu_load: [],
  memory_used: [],
  memory_free: []
};
var STATS_SERIES_MAX = 60; // keep last 60 samples (~1 min at 1s sampling)

// Chart.js instances
window._charts = window._charts || {};

function pushStat(seriesName, value) {
  try {
    var s = window._stats_series[seriesName] = window._stats_series[seriesName] || [];
    s.push(Number(value) || 0);
    if (s.length > STATS_SERIES_MAX) s.shift();
  } catch(e) {}
}

// Initialize modern Chart.js charts for statistics
function initStatsCharts() {
  try {
    // Network chart (Nodes & Routes)
    var networkCtx = document.getElementById('network-chart');
    if (networkCtx) {
      window._charts.network = new Chart(networkCtx, {
        type: 'line',
        data: {
          labels: Array.from({length: STATS_SERIES_MAX}, (_, i) => i + 1),
          datasets: [{
            label: 'Nodes',
            data: [],
            borderColor: '#007bff',
            backgroundColor: 'rgba(0, 123, 255, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 4
          }, {
            label: 'Routes',
            data: [],
            borderColor: '#28a745',
            backgroundColor: 'rgba(40, 167, 69, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            intersect: false,
            mode: 'index'
          },
          plugins: {
            legend: {
              display: true,
              position: 'top'
            },
            tooltip: {
              enabled: true,
              callbacks: {
                title: function(context) {
                  return 'Sample ' + context[0].dataIndex;
                }
              }
            }
          },
          scales: {
            x: {
              display: false
            },
            y: {
              beginAtZero: true,
              grid: {
                color: 'rgba(0,0,0,0.05)'
              }
            }
          },
          animation: {
            duration: 0 // Disable animations for real-time updates
          }
        }
      });
    }

    // System resources chart (CPU & Memory)
    var systemCtx = document.getElementById('system-chart');
    if (systemCtx) {
      window._charts.system = new Chart(systemCtx, {
        type: 'line',
        data: {
          labels: Array.from({length: STATS_SERIES_MAX}, (_, i) => i + 1),
          datasets: [{
            label: 'CPU Load',
            data: [],
            borderColor: '#fd7e14',
            backgroundColor: 'rgba(253, 126, 20, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 4
          }, {
            label: 'Memory Used (%)',
            data: [],
            borderColor: '#dc3545',
            backgroundColor: 'rgba(220, 53, 69, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            intersect: false,
            mode: 'index'
          },
          plugins: {
            legend: {
              display: true,
              position: 'top'
            }
          },
          scales: {
            x: {
              display: false
            },
            y: {
              beginAtZero: true,
              max: 100,
              grid: {
                color: 'rgba(0,0,0,0.05)'
              }
            }
          },
          animation: {
            duration: 0
          }
        }
      });
    }

    // Fetch operations chart
    var fetchCtx = document.getElementById('fetch-chart');
    if (fetchCtx) {
      window._charts.fetch = new Chart(fetchCtx, {
        type: 'line',
        data: {
          labels: Array.from({length: STATS_SERIES_MAX}, (_, i) => i + 1),
          datasets: [{
            label: 'Queue Length',
            data: [],
            borderColor: '#6f42c1',
            backgroundColor: 'rgba(111, 66, 193, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 4
          }, {
            label: 'Processing',
            data: [],
            borderColor: '#20c997',
            backgroundColor: 'rgba(32, 201, 151, 0.1)',
            borderWidth: 2,
            fill: true,
            tension: 0.4,
            pointRadius: 0,
            pointHoverRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            intersect: false,
            mode: 'index'
          },
          plugins: {
            legend: {
              display: true,
              position: 'top'
            }
          },
          scales: {
            x: {
              display: false
            },
            y: {
              beginAtZero: true,
              grid: {
                color: 'rgba(0,0,0,0.05)'
              }
            }
          },
          animation: {
            duration: 0
          }
        }
      });
    }
  } catch(e) {
    console.error('Failed to initialize stats charts:', e);
  }
}

// Update chart data
function updateStatsCharts() {
  try {
    // Update network chart
    if (window._charts.network) {
      window._charts.network.data.datasets[0].data = window._stats_series.olsr_nodes.slice(-STATS_SERIES_MAX);
      window._charts.network.data.datasets[1].data = window._stats_series.olsr_routes.slice(-STATS_SERIES_MAX);
      window._charts.network.update('none');
    }

    // Update system chart
    if (window._charts.system) {
      window._charts.system.data.datasets[0].data = window._stats_series.cpu_load.slice(-STATS_SERIES_MAX);
      window._charts.system.data.datasets[1].data = window._stats_series.memory_used.slice(-STATS_SERIES_MAX);
      window._charts.system.update('none');
    }

    // Update fetch chart
    if (window._charts.fetch) {
      window._charts.fetch.data.datasets[0].data = window._stats_series.fetch_queued.slice(-STATS_SERIES_MAX);
      window._charts.fetch.data.datasets[1].data = window._stats_series.fetch_processing.slice(-STATS_SERIES_MAX);
      window._charts.fetch.update('none');
    }
  } catch(e) {
    console.error('Failed to update stats charts:', e);
  }
}

// Update trend indicators for nodes and routes
function updateTrendIndicators(routesArr, nodesArr) {
  try {
    function statsFromArr(arr) {
      if (!arr || !arr.length) return { min:0, max:0, avg:0, trend:0 };
      var min = Math.min.apply(null, arr);
      var max = Math.max.apply(null, arr);
      var sum = arr.reduce(function(a,b){return a+(Number(b)||0);},0);
      var avg = sum / arr.length;
      var trend = 0;
      if (arr.length >= 2) {
        var last = Number(arr[arr.length-1])||0;
        var prior = Number(arr[Math.max(0, arr.length-6)])||0; // compare against ~6 samples ago
        trend = last - prior;
      }
      return { min: Math.round(min), max: Math.round(max), avg: Math.round(avg*10)/10, trend: Math.round(trend) };
    }
    
    var rStats = statsFromArr(routesArr.slice(-10));
    var nStats = statsFromArr(nodesArr.slice(-10));
    
    // Update trend elements
    var routesTrendEl = document.getElementById('routes-trend'); 
    if (routesTrendEl) {
      routesTrendEl.className = '';
      if (rStats.trend > 0) { 
        routesTrendEl.textContent = '▲ ' + String(rStats.trend); 
        routesTrendEl.classList.add('trend-up'); 
      } else if (rStats.trend < 0) { 
        routesTrendEl.textContent = '▼ ' + String(Math.abs(rStats.trend)); 
        routesTrendEl.classList.add('trend-down'); 
      } else { 
        routesTrendEl.textContent = '◦'; 
        routesTrendEl.classList.add('trend-flat'); 
      }
    }
    
    var nodesTrendEl = document.getElementById('nodes-trend'); 
    if (nodesTrendEl) {
      nodesTrendEl.className = '';
      if (nStats.trend > 0) { 
        nodesTrendEl.textContent = '▲ ' + String(nStats.trend); 
        nodesTrendEl.classList.add('trend-up'); 
      } else if (nStats.trend < 0) { 
        nodesTrendEl.textContent = '▼ ' + String(Math.abs(nStats.trend)); 
        nodesTrendEl.classList.add('trend-down'); 
      } else { 
        nodesTrendEl.textContent = '◦'; 
        nodesTrendEl.classList.add('trend-flat'); 
      }
    }
  } catch(e) {}
}

// Single flexible card renderer: renders a Bootstrap-style panel into a container.
// Supports both styles used across the codebase.
// opts: {
//   container: element or id string,
//   panelClass: optional panel class (default 'panel panel-default'),
//   title, subtitle,
//   bodyStyle: cssText for body,
//   contentHTML: optional HTML string to place into body,
//   smallHelp: optional help HTML appended to body,
//   render: optional function(bodyEl, headerRightEl) to programmatically populate body/header
// }
function renderCard(opts) {
  try {
    if (!opts) return;
    var container = null;
    if (typeof opts.container === 'string') container = document.getElementById(opts.container);
    else container = opts.container || null;
    // fallback to containerId for older call-sites
    if (!container && opts.containerId) container = document.getElementById(opts.containerId);
    if (!container) return;

  // clear and build panel
  clearChildren(container);
    var panel = document.createElement('div'); panel.className = opts.panelClass || 'panel panel-default';
    var heading = document.createElement('div'); heading.className = 'panel-heading';
    heading.style.display = 'flex'; heading.style.justifyContent = 'space-between'; heading.style.alignItems = 'center';

    var titleWrap = document.createElement('div');
    if (opts.title) { var title = document.createElement('div'); title.style.fontWeight = '600'; title.style.marginBottom = '4px'; title.textContent = opts.title; titleWrap.appendChild(title); }
    if (opts.subtitle) { var sub = document.createElement('div'); sub.style.fontSize = '12px'; sub.style.color = '#666'; sub.textContent = opts.subtitle; titleWrap.appendChild(sub); }
    heading.appendChild(titleWrap);

    var headerRight = document.createElement('div'); headerRight.style.display = 'flex'; headerRight.style.gap = '8px'; headerRight.style.alignItems = 'center'; heading.appendChild(headerRight);
    panel.appendChild(heading);

    var body = document.createElement('div'); body.className = 'panel-body'; if (opts.bodyStyle) body.style.cssText = opts.bodyStyle;
  // contentHTML convenience (use textContent to avoid raw HTML)
  if (opts.contentHTML) { var content = document.createElement('div'); content.textContent = opts.contentHTML; body.appendChild(content); }

    // render callback may populate body and headerRight
    try { if (typeof opts.render === 'function') opts.render(body, headerRight); } catch (e) { /* swallow UI render errors */ }

  if (opts.smallHelp) { var help = document.createElement('div'); help.className = 'small-muted'; help.style.marginTop = '8px'; help.textContent = opts.smallHelp; body.appendChild(help); }

    panel.appendChild(body);
    container.appendChild(panel);
  } catch (e) { /* ignore */ }
}

// Hook into updateUI to sample stats when status payload contains them
var _original_updateUI = updateUI;
updateUI = function(data) {
  try {
    // sample olsr routes/nodes if available in payload
    try {
      var routes = 0; var nodes = 0;
      if (data.links && Array.isArray(data.links)) {
        // count unique routes approximated by sum of link.routes
        routes = data.links.reduce(function(acc,l){ return acc + (parseInt(l.routes,10)||0); }, 0);
        nodes = data.links.reduce(function(acc,l){ return acc + (parseInt(l.nodes,10)||0); }, 0);
      } else {
        if (typeof data.olsr_routes_count === 'number') {
          routes = data.olsr_routes_count;
        }
        if (typeof data.olsr_nodes_count === 'number') {
          nodes = data.olsr_nodes_count;
        }
      }
      pushStat('olsr_routes', routes);
      pushStat('olsr_nodes', nodes);
      // Update compact header badges when available
      try {
        var bn = document.getElementById('badge-nodes'); if (bn) { bn.textContent = 'Nodes: ' + String(nodes); }
        var br = document.getElementById('badge-routes'); if (br) { br.textContent = 'Routes: ' + String(routes); }
      } catch(e) {}
    } catch(e) {}
    // sample fetch queue metrics if provided
    try {
      var fq = (data.fetch_stats && (data.fetch_stats.queued_count || data.fetch_stats.queue_length || data.fetch_stats.queued)) || 0;
      var fp = (data.fetch_stats && (data.fetch_stats.processing_count || data.fetch_stats.processing || data.fetch_stats.in_progress)) || 0;
      pushStat('fetch_queued', fq);
      pushStat('fetch_processing', fp);
    } catch(e) {}
    
    // sample CPU load from uptime string
    try {
      if (data.uptime_linux) {
        var uptimeMatch = data.uptime_linux.match(/load average:\s*([0-9.]+),\s*([0-9.]+),\s*([0-9.]+)/);
        if (uptimeMatch) {
          var load1m = parseFloat(uptimeMatch[1]); // Keep as raw load average
          pushStat('cpu_load', load1m);
        }
      }
    } catch(e) {}
    
    // sample memory usage (if available in future backend updates)
    try {
      // For now, we'll simulate or wait for backend memory data
      // pushStat('memory_used', memoryPercent);
      // pushStat('memory_free', freePercent);
    } catch(e) {}
    
    // Update modern charts
    try {
      updateStatsCharts();
    } catch(e) {}
    
    // Update UI elements for nodes and routes
    try {
      var routesArr = window._stats_series.olsr_routes || [];
      var nodesArr = window._stats_series.olsr_nodes || [];
      var routesCur = routesArr.length ? routesArr[routesArr.length-1] : 0;
      var nodesCur = nodesArr.length ? nodesArr[nodesArr.length-1] : 0;
      var routesEl = document.getElementById('routes-cur'); if (routesEl) routesEl.textContent = String(routesCur);
      var nodesEl = document.getElementById('nodes-cur'); if (nodesEl) nodesEl.textContent = String(nodesCur);
      
      // Update CPU and memory displays
      var cpuArr = window._stats_series.cpu_load || [];
      var cpuCur = cpuArr.length ? cpuArr[cpuArr.length-1] : 0;
      var cpuEl = document.getElementById('cpu-load'); if (cpuEl) cpuEl.textContent = cpuCur.toFixed(1) + '%';
      
      var memEl = document.getElementById('memory-usage'); 
      try {
        var memArr = window._stats_series.memory_used || [];
        var memCur = memArr.length ? memArr[memArr.length-1] : null;
        if (memCur === null && data && (typeof data.memory_used_percent !== 'undefined')) memCur = Number(data.memory_used_percent);
        if (memEl) memEl.textContent = (memCur === null || typeof memCur === 'undefined') ? 'N/A' : (Number(memCur).toFixed(1) + '%');
      } catch(e) { if (memEl) memEl.textContent = 'N/A'; }
      
      // Update fetch stats
      var queueArr = window._stats_series.fetch_queued || [];
      var procArr = window._stats_series.fetch_processing || [];
      var queueCur = queueArr.length ? queueArr[queueArr.length-1] : 0;
      var procCur = procArr.length ? procArr[procArr.length-1] : 0;
      var queueEl = document.getElementById('queue-length'); if (queueEl) queueEl.textContent = String(queueCur);
      var procEl = document.getElementById('processing-count'); if (procEl) procEl.textContent = String(procCur);
      
      // Calculate success rate
      var successEl = document.getElementById('success-rate');
      if (successEl && data.fetch_stats) {
        var total = (data.fetch_stats.successes || 0) + (data.fetch_stats.retries || 0) + (data.fetch_stats.dropped || 0);
        if (total > 0) {
          var rate = ((data.fetch_stats.successes || 0) / total * 100).toFixed(1) + '%';
          successEl.textContent = rate;
        } else {
          successEl.textContent = 'N/A';
        }
      }
      
      // Update trend indicators
      updateTrendIndicators(routesArr, nodesArr);
    } catch(e) {}
  } catch(e) {}
  // Only call the original full updateUI when the payload looks like a full status
  try {
    var looksFull = (data && (data.hostname || data.devices || data.links || data.ip || data.uptime || data.olsr2_on || data.olsrd_on));
    if (looksFull) {
      try { _original_updateUI(data); } catch(e) {}
    } else {
      // minimal stats-only payload -> do not overwrite the full UI
      if (window._uiDebug) console.debug('Skipping full updateUI for stats-only payload');
    }
  } catch(e) {}
};

  // Lightweight polling to keep statistics live: fetch /status/lite periodically and feed updateUI
  window._stats_poll_interval_ms = 5000; // enforce 5s polling as requested
  function _statsPollOnce() {
    fetch('/status/lite', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(s){ try { if (s) {
      // Map minimal stats payload into shape expected by updateUI
      var mapped = {};
      if (typeof s.olsr_routes_count !== 'undefined') mapped.olsr_routes_count = s.olsr_routes_count;
      if (typeof s.olsr_nodes_count !== 'undefined') mapped.olsr_nodes_count = s.olsr_nodes_count;
      if (s.fetch_stats) mapped.fetch_stats = s.fetch_stats;
      // Extract load average from uptime_linux
      if (s.uptime_linux) {
        var loadMatch = s.uptime_linux.match(/load average:\s*([0-9.]+),/);
        if (loadMatch && loadMatch[1]) {
          var loadAvg = parseFloat(loadMatch[1]);
          if (!isNaN(loadAvg)) {
            pushStat('cpu_load', loadAvg);
          }
        }
      }
      // If lite payload lacks node/route counts, fall back to /status/stats for those values
      if (typeof mapped.olsr_routes_count === 'undefined' || typeof mapped.olsr_nodes_count === 'undefined') {
        fetch('/status/stats', {cache:'no-store'}).then(function(r2){ return r2.json(); }).then(function(st){ try {
          if (st) {
            if (typeof st.olsr_routes_count !== 'undefined') mapped.olsr_routes_count = st.olsr_routes_count;
            if (typeof st.olsr_nodes_count !== 'undefined') mapped.olsr_nodes_count = st.olsr_nodes_count;
            if (st.fetch_stats && !mapped.fetch_stats) mapped.fetch_stats = st.fetch_stats;
            // Push memory stats from /status/stats when available
            if (typeof st.memory_used_percent !== 'undefined') pushStat('memory_used', Number(st.memory_used_percent));
            if (typeof st.memory_free_kb !== 'undefined' && typeof st.memory_total_kb !== 'undefined') {
              var freePerc = (Number(st.memory_free_kb) / Number(st.memory_total_kb)) * 100.0;
              pushStat('memory_free', freePerc);
            }
          }
          updateUI(mapped);
        } catch(e) { updateUI(mapped); } }).catch(function(){ updateUI(mapped); });
      } else {
        // Push memory stats from /status/lite when available
        if (typeof s.memory_used_percent !== 'undefined') pushStat('memory_used', Number(s.memory_used_percent));
        if (typeof s.memory_free_kb !== 'undefined' && typeof s.memory_total_kb !== 'undefined') {
          var freePerc2 = (Number(s.memory_free_kb) / Number(s.memory_total_kb)) * 100.0;
          pushStat('memory_free', freePerc2);
        }
        updateUI(mapped);
      }
    } } catch(e) {} }).catch(function(){});
  }
  function _startStatsPoll() {
    if (window._stats_poll_handle) return;
    _statsPollOnce();
    window._stats_poll_handle = setInterval(_statsPollOnce, window._stats_poll_interval_ms);
  }
  function _stopStatsPoll(){ if (window._stats_poll_handle) { clearInterval(window._stats_poll_handle); window._stats_poll_handle = null; } }

// Links live polling: fetch '/status/links_live' periodically and update table
if (typeof window._links_poll_interval_ms === 'undefined') window._links_poll_interval_ms = 10000; // 10s default
function _linksPollOnce() {
  try {
    // Only poll when OLSR Links tab is visible to avoid unnecessary network
    var pane = document.getElementById('tab-olsr');
    if (!pane || pane.style.display === 'none' || pane.classList.contains('hidden')) return;
    fetch('/status/links_live', {cache:'no-store'}).then(function(r){ if (!r || !r.ok) throw new Error('HTTP '+(r&&r.status)); return r.json(); }).then(function(obj){
      try {
        if (obj && obj.links && Array.isArray(obj.links)) {
          window._olsr_links = obj.links.slice();
          try { populateOlsrLinksTable(window._olsr_links); } catch(e) {}
        }
      } catch(e) {}
    }).catch(function(){ /* ignore transient errors */ });
  } catch(e) {}
}
function startLinksPoll() {
  if (window._links_poll_handle) return;
  // pick up user-configured interval if present
  try {
    var iv = parseInt(localStorage.getItem('links_live_interval_s'), 10);
    if (!isNaN(iv) && iv > 0) window._links_poll_interval_ms = iv * 1000;
  } catch(e) {}
  try { _linksPollOnce(); } catch(e) {}
  window._links_poll_handle = setInterval(_linksPollOnce, window._links_poll_interval_ms);
}
function stopLinksPoll() { if (window._links_poll_handle) { clearInterval(window._links_poll_handle); window._links_poll_handle = null; } }

// update last-updated timestamp helper (called from updateUI)
function setLastUpdated(ts) {
  try {
    var el = document.getElementById('last-updated');
    var text = ts || new Date().toLocaleString();
    if (el) el.textContent = text;
    // also mirror a compact last-updated timestamp into the sticky footer center
    try { setFooterText('footer-last-updated', text); } catch(e) { try { var fel = document.getElementById('footer-last-updated'); if (fel) fel.textContent = text; } catch(e) {} }
  } catch(e) {}
}

// Helper to set footer textContent and add a title when the content is visually truncated
function setFooterText(id, text) {
  try {
    var el = document.getElementById(id);
    if (!el) return;
    // set text content first
    el.textContent = String(text == null ? '' : text);
    // If the element has the truncation class, set title attribute so the full text appears on hover
    try {
      if (el.classList && el.classList.contains('footer-trunc')) {
        el.setAttribute('title', String(text == null ? '' : text));
      } else {
        el.removeAttribute('title');
      }
    } catch(e) {}
  } catch(e) {}
}

function showActionToast(msg, ms) {
  try {
    var toast = document.getElementById('action-toast'); var body = document.getElementById('action-toast-body');
    if (!toast || !body) return;
    body.textContent = msg || '';
    toast.style.display = 'block';
    toast.style.opacity = '1';
    if (window._actionToastTimer) { clearTimeout(window._actionToastTimer); window._actionToastTimer = null; }
    window._actionToastTimer = setTimeout(function(){ try { toast.style.opacity='0'; setTimeout(function(){ toast.style.display='none'; },300); } catch(e){} }, ms || 2000);
  } catch(e) {}
}



// Render fetch queue metrics (provided by backend in status.fetch_stats)
function populateFetchStats(fs) {
  try {
    var tabWrap = document.getElementById('fetch-tab-wrap'); if (!tabWrap) return;
    var container = document.getElementById('fetch-stats');
    if (!container) {
      container = document.createElement('div');
      container.id = 'fetch-stats';
      container.style.margin = '6px 0 12px 0';
      tabWrap.appendChild(container);
    }
  if (!fs || (typeof fs === 'object' && Object.keys(fs).length === 0)) { container.style.display = 'none'; return; }
  container.style.display = '';

    // Normalize likely field names from backend
    var queued = fs.queued_count || fs.queue_length || fs.queue_len || fs.queued || 0;
    var processing = fs.processing_count || fs.in_progress || fs.processing || 0;
    var dropped = fs.dropped_count || fs.dropped || 0;
    var retries = fs.retry_count || fs.retries || 0;
    var processed = fs.total_processed || fs.processed || 0;
    var successes = fs.successes || fs.fetch_successes || 0;
    // New debug counters provided by backend
    var enqueued_total = fs.enqueued || fs.enqueued_total || 0;
    var enqueued_nodedb = fs.enqueued_nodedb || 0;
    var enqueued_discover = fs.enqueued_discover || 0;
    var processed_total = fs.processed || fs.processed_total || 0;
    var processed_nodedb = fs.processed_nodedb || 0;
    var processed_discover = fs.processed_discover || 0;

    // thresholds (backend may export thresholds for front-end convenience)
    var thresholds = (fs.thresholds && typeof fs.thresholds === 'object') ? fs.thresholds : {};
    var q_warn = thresholds.queue_warn || 50;
    var q_crit = thresholds.queue_crit || 200;
    var d_warn = thresholds.dropped_warn || 10;

    // Render using renderCard for consistent layout and easier reuse
    renderCard({
      container: container,
      title: 'Fetch Queue',
      panelClass: 'panel panel-default',
      bodyStyle: 'padding:10px',
      render: function(body, headerRight) {
        // left column (badges + progress)
        var left = document.createElement('div'); left.style.display='inline-block'; left.style.width='62%'; left.style.verticalAlign='top';
        var badges = document.createElement('div'); badges.style.marginBottom='8px';
  function mkBadgeNode(label, val, cls) { var sp=document.createElement('span'); sp.className='fetch-badge '+(cls||''); sp.style.marginRight='6px'; var lbl=document.createElement('span'); lbl.textContent = label + ':'; var strong=document.createElement('strong'); strong.style.marginLeft='6px'; strong.textContent = String(val); sp.appendChild(lbl); sp.appendChild(strong); return sp; }
        var qcls = queued >= q_crit ? 'crit' : (queued >= q_warn ? 'warn' : '');
        var dcls = dropped >= d_warn ? 'warn' : '';
        badges.appendChild(mkBadgeNode('Queued', queued, qcls));
        badges.appendChild(mkBadgeNode('Processing', processing));
        badges.appendChild(mkBadgeNode('Dropped', dropped, dcls));
        badges.appendChild(mkBadgeNode('Retries', retries));
        badges.appendChild(mkBadgeNode('Processed', processed));
        left.appendChild(badges);
        var denom = q_crit > 0 ? q_crit : 200;
        var pct = Math.min(100, Math.round((queued / denom) * 100));
        var prog = document.createElement('div'); prog.className='progress'; prog.style.height='16px'; prog.style.marginBottom='6px';
        var progBar = document.createElement('div'); var progClass = pct >= 100 ? 'progress-bar-danger' : (pct >= Math.round((q_warn/denom)*100) ? 'progress-bar-warning' : 'progress-bar-success');
        progBar.className = 'progress-bar '+progClass; progBar.setAttribute('role','progressbar'); progBar.setAttribute('aria-valuenow', String(pct)); progBar.setAttribute('aria-valuemin','0'); progBar.setAttribute('aria-valuemax','100'); progBar.style.width = pct + '%';
        prog.appendChild(progBar); left.appendChild(prog);
        var pctNode = document.createElement('div'); pctNode.style.marginTop='4px'; pctNode.textContent = pct + '%'; left.appendChild(pctNode);
        body.appendChild(left);

        // right column (small table)
        var right = document.createElement('div'); right.style.display='inline-block'; right.style.width='36%'; right.style.paddingLeft='10px'; right.style.verticalAlign='top';
        var table = document.createElement('table'); table.className = 'table table-condensed'; table.style.margin='0';
        var tb = document.createElement('tbody');
        function mkRow(k,v){ var r=document.createElement('tr'); var th=document.createElement('th'); if (k==='Queued') th.style.width='55%'; th.textContent = k; var td=document.createElement('td'); td.textContent = String(v); r.appendChild(th); r.appendChild(td); return r; }
        tb.appendChild(mkRow('Queued', queued)); tb.appendChild(mkRow('Processing', processing)); tb.appendChild(mkRow('Dropped', dropped)); tb.appendChild(mkRow('Retries', retries)); tb.appendChild(mkRow('Processed', processed)); tb.appendChild(mkRow('Successes', successes));
        table.appendChild(tb); right.appendChild(table); body.appendChild(right);

        // headerRight controls (preserve element IDs for existing wiring)
  var refreshBtn = document.createElement('button'); refreshBtn.id='fetch-stats-refresh'; refreshBtn.className='btn btn-xs btn-default'; var refreshI=document.createElement('i'); refreshI.className='glyphicon glyphicon-refresh'; refreshBtn.appendChild(refreshI);
        var debugBtn = document.createElement('button'); debugBtn.id='fetch-stats-debug'; debugBtn.className='btn btn-xs btn-default'; debugBtn.textContent='Debug';
        var sel = document.createElement('select'); sel.id='fetch-stats-interval'; sel.className='input-sm form-control'; sel.style.width='120px'; sel.style.display='inline-block'; sel.style.marginRight='6px';
        [['0','Auto off'],['5000','5s'],['10000','10s'],['15000','15s'],['30000','30s'],['60000','60s'],['120000','2m'],['300000','5m']].forEach(function(o){ var opt=document.createElement('option'); opt.value=o[0]; opt.textContent=o[1]; sel.appendChild(opt); });
        var autoBtn = document.createElement('button'); autoBtn.id='fetch-stats-autorefresh'; autoBtn.className='btn btn-xs btn-default'; autoBtn.title='Toggle auto-refresh'; autoBtn.textContent='Auto';
        headerRight.appendChild(refreshBtn); headerRight.appendChild(debugBtn); headerRight.appendChild(sel); headerRight.appendChild(autoBtn);

        // thresholds footer
  var thr = document.createElement('div'); thr.className='small-muted'; thr.style.marginTop='8px'; thr.textContent = 'Thresholds: warn=' + q_warn + '  crit=' + q_crit + '  dropped_warn=' + d_warn; body.appendChild(thr);
      }
    });

    // wire actions: refresh
    var ref = document.getElementById('fetch-stats-refresh');
    if (ref) ref.addEventListener('click', function(){
      try { ref.disabled = true; } catch(e){}
      fetch('/status/lite', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(s){ try { if (s.fetch_stats) populateFetchStats(s.fetch_stats); } catch(e){} }).catch(function(){
    safeFetchStatus({cache:'no-store'}).then(function(s){ try{ if (s.fetch_stats) populateFetchStats(s.fetch_stats); }catch(e){} });
      }).finally(function(){ try{ ref.disabled=false; }catch(e){} });
    });

    // Auto-refresh toggle logic
    var autoBtn = document.getElementById('fetch-stats-autorefresh');
    var intervalSel = document.getElementById('fetch-stats-interval');
    // derive default interval: prefer persisted localStorage, then backend hint, then default 15000
    try {
      var persisted = parseInt(localStorage.getItem('fetch_auto_interval_ms'), 10);
      if (!isNaN(persisted)) {
        window._fetch_auto_interval_ms = persisted;
      } else if (fs && fs.fetch_auto_refresh_ms) {
        window._fetch_auto_interval_ms = parseInt(fs.fetch_auto_refresh_ms, 10) || 15000;
      } else if (!window._fetch_auto_interval_ms) {
        window._fetch_auto_interval_ms = 15000; // default 15s
      }
    } catch(e) { if (!window._fetch_auto_interval_ms) window._fetch_auto_interval_ms = 15000; }
    if (!window._fetch_auto_handle) window._fetch_auto_handle = null;
    // set selector to current value
    try { if (intervalSel) intervalSel.value = String(window._fetch_auto_interval_ms || 0); } catch(e){}
    // change handler: persist & restart if needed
    if (intervalSel) intervalSel.addEventListener('change', function(){
      try {
        var v = parseInt(intervalSel.value, 10) || 0;
        window._fetch_auto_interval_ms = v;
        localStorage.setItem('fetch_auto_interval_ms', String(v));
        // if running, restart with new interval
        if (window._fetch_auto_handle) {
          clearInterval(window._fetch_auto_handle); window._fetch_auto_handle = null;
          if (v > 0) window._fetch_auto_handle = setInterval(function(){ try { document.getElementById('fetch-stats-refresh').click(); } catch(e){} }, v);
        }
      } catch(e){}
    });
    function startAutoRefresh() {
      if (window._fetch_auto_handle) return;
      if (!window._fetch_auto_interval_ms || window._fetch_auto_interval_ms <= 0) return; // disabled
      window._fetch_auto_handle = setInterval(function(){ try { document.getElementById('fetch-stats-refresh').click(); } catch(e){} }, window._fetch_auto_interval_ms);
      if (autoBtn) autoBtn.classList.add('btn-success');
    }
    function stopAutoRefresh() {
      if (!window._fetch_auto_handle) return;
      clearInterval(window._fetch_auto_handle); window._fetch_auto_handle = null;
      if (autoBtn) autoBtn.classList.remove('btn-success');
    }
    if (autoBtn) autoBtn.addEventListener('click', function(){ if (window._fetch_auto_handle) stopAutoRefresh(); else startAutoRefresh(); });

    // debug modal
    var dbg = document.getElementById('fetch-stats-debug');
    if (dbg) dbg.addEventListener('click', function(){
      var modal = document.getElementById('fetch-debug-modal'); var body = document.getElementById('fetch-debug-body');
      if (!modal || !body) return;
  body.textContent = 'Loading...'; showModal('fetch-debug-modal');
      fetch('/fetch_debug', {cache:'no-store'}).then(function(r){ return r.text(); }).then(function(t){ try { var obj = JSON.parse(t); body.textContent = JSON.stringify(obj, null, 2); } catch(e) { body.textContent = t; } }).catch(function(e){ body.textContent = 'ERR: '+e; });
    });

  // Update top header/nav indicator based on severity
    {
  // (status-summary card removed; fetch stats now live in the Fetch Queue tab)
      var hostEl = document.getElementById('nav-host');
      if (hostEl) {


      // Render a small SVG sparkline into an <svg> element with given id
      function renderSparkline(svgId, series, color) {
        var svg = document.getElementById(svgId);
        if (!svg) return;
        var viewW = 320, viewH = 100;
        svg.setAttribute('viewBox', '0 0 ' + viewW + ' ' + viewH);
        while (svg.firstChild) svg.removeChild(svg.firstChild);
        var data = (series || []).slice(-10);
        if (!data.length) return;
        var minY = Math.min.apply(null, data), maxY = Math.max.apply(null, data);
        if (minY === maxY) { minY = 0; maxY = maxY + 1; }
        var pad = 12;
        var points = data.map(function(v, i){
          var x = pad + ((viewW-2*pad) * i/(data.length-1));
          var y = viewH - pad - ((viewH-2*pad) * (v - minY)/(maxY - minY));
          return [x,y];
        });
        // background polyline area
        var areaPts = points.map(function(p){ return p[0]+','+p[1]; }).join(' ');
        var area = document.createElementNS('http://www.w3.org/2000/svg','polygon');
        area.setAttribute('points', pad+','+(viewH-pad)+' '+ areaPts +' '+(viewW-pad)+','+(viewH-pad));
        area.setAttribute('fill', color); area.setAttribute('fill-opacity', '0.08'); svg.appendChild(area);
        // line path
        var pathD = points.map(function(p,i){ return (i===0? 'M':'L') + p[0] + ' ' + p[1]; }).join(' ');
        var path = document.createElementNS('http://www.w3.org/2000/svg','path');
        path.setAttribute('d', pathD); path.setAttribute('stroke', color); path.setAttribute('stroke-width','2'); path.setAttribute('fill','none'); svg.appendChild(path);
        // points
        points.forEach(function(p){ var c = document.createElementNS('http://www.w3.org/2000/svg','circle'); c.setAttribute('cx', p[0]); c.setAttribute('cy', p[1]); c.setAttribute('r','3'); c.setAttribute('fill', color); svg.appendChild(c); });
        // min/max labels
        var txtMin = document.createElementNS('http://www.w3.org/2000/svg','text'); txtMin.setAttribute('x', 4); txtMin.setAttribute('y', viewH-pad); txtMin.setAttribute('fill','#666'); txtMin.setAttribute('font-size','10'); txtMin.textContent = String(Math.round(minY)); svg.appendChild(txtMin);
        var txtMax = document.createElementNS('http://www.w3.org/2000/svg','text'); txtMax.setAttribute('x', 4); txtMax.setAttribute('y', pad+8); txtMax.setAttribute('fill','#666'); txtMax.setAttribute('font-size','10'); txtMax.textContent = String(Math.round(maxY)); svg.appendChild(txtMax);
  }
      function extractAllTopLevelJSON(s) {
        var out = [];
        if (!s || !s.length) return out;
        var len = s.length;
        for (var i = 0; i < len; i++) {
          var ch = s[i];
          if (ch !== '{' && ch !== '[') continue;
          var open = ch; var close = (open === '{') ? '}' : ']';
          var depth = 1;
          for (var j = i + 1; j < len; j++) {
            var cj = s[j];
            if (cj === open) depth++;
            else if (cj === close) depth--;
            if (depth === 0) {
              var cand = s.substring(i, j + 1);
              try {
                var obj = JSON.parse(cand);
                out.push(obj);
              } catch (err) {
                // ignore parse errors for this candidate
              }
              i = j; // advance outer loop past this object
              break;
            }
          }
        }
        return out;
      }
      try {
        var candidates = extractAllTopLevelJSON(String(text || ''));
        if (!candidates || candidates.length === 0) return null;
        if (candidates.length === 1) return candidates[0];
        var preferredKeys = ['hostname','devices','links','fetch_stats','ip','uptime'];
        for (var k = candidates.length - 1; k >= 0; k--) {
          var c = candidates[k];
          if (c && typeof c === 'object') {
            for (var pi = 0; pi < preferredKeys.length; pi++) {
              if (typeof c[preferredKeys[pi]] !== 'undefined') return c;
            }
          }
        }
        var allDevices = true;
        for (var ii = 0; ii < candidates.length; ii++) {
          var cc = candidates[ii];
          if (!cc || typeof cc !== 'object') { allDevices = false; break; }
          if (typeof cc.ipv4 === 'undefined' && typeof cc.hwaddr === 'undefined' && typeof cc.ip === 'undefined') { allDevices = false; break; }
        }
        if (allDevices) return { devices: candidates };
        return candidates[candidates.length - 1];
      } catch(_e) { return null; }
    }
  }
  fetch('/capabilities', {cache: 'no-store'})
    .then(function(r) { return r.text(); })
    .then(function(capText) {
      var caps = safeParse('capabilities', capText) || {};
      // show/hide traceroute tab
      try {
        var trTab = document.querySelector('#mainTabs a[href="#tab-traceroute"]');
        if (trTab) trTab.parentElement.style.display = (caps.traceroute? '': 'none');
        var adminTabLink = document.getElementById('tab-admin-link');
        if (adminTabLink) adminTabLink.style.display = (caps.show_admin_link? '' : 'none');
      } catch(e){}
  var data = { hostname: '', ip: '', uptime: '', devices: [], airos: {}, olsr2_on: false, olsrd_on: false, olsr2info: '', admin: null };
  // Fetch nodedb early so we can enrich hostnames when rendering
  try { fetch('/nodedb.json', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(nb){ window._nodedb_cache = nb || {}; }).catch(function(){}); } catch(e){}
  // Fetch summary first for fast paint (use tolerant parser because some devices
  // emit concatenated top-level JSON fragments). We try to keep the fast-path
  // but avoid r.json() which will throw on non-strict JSON streams.
  try {
    // Fast-path: fetch a lightweight summary text and render immediately.
    // Keep the raw text so we can pass it to safeFetchStatus and avoid a
    // second network request when the full parsing happens below.
    fetch('/status/lite', {cache: 'no-store'}).then(function(r){ return r.text(); }).then(function(t){
      try {
        var s = safeParse('status-lite', t) || {};
        if (s.hostname) data.hostname = s.hostname;
        if (s.ip) data.ip = s.ip;
        if (s.uptime_linux) { data.uptime_linux = s.uptime_linux; }
        updateUI(data);
      } catch(e) { /* ignore fast-path errors */ }
      // store the fast text so the robust parser can reuse it without re-fetching
      data._fast_status_text = t;
    }).catch(function(){});
  } catch(e) {}
  // Fetch remaining heavier status in background (full status still used for deep data)
  // Use safeFetchStatus which already implements robust extraction of the
  // last/top-level JSON object and candidate selection. If we have the
  // fast-path text available, pass it in to avoid a duplicate network request.
  var maybeText = data._fast_status_text;
  safeFetchStatus(maybeText || {cache: 'no-store'})
        .then(function(status) {
          // status is already parsed or null on failure
          if (!status) return; // abort if irreparable
            try { if (status.fetch_stats) populateFetchStats(status.fetch_stats); else populateFetchStats({}); } catch(e){}
          data.hostname = status.hostname || '';
          data.ip = status.ip || '';
          data.uptime = status.uptime || '';
          data.devices = status.devices || [];
          data.airos = status.airosdata || {};
          // ensure defaults so updateUI can safely use them
          data.default_route = status.default_route || {};
          data.links = status.links || [];
      if (status.olsr2_on) {
            data.olsr2_on = true;
            // OLSRd2-Links tab removed
            fetch('/olsr2', {cache: 'no-store'})
              .then(function(r) { return r.text(); })
              .then(function(t) {
                data.olsr2info = t;
                updateUI(data);
                try { if (data.links && data.links.length) populateOlsrLinksTable(data.links); } catch(e){}
              }).catch(function(){
                // If /olsr2 fetch failed, still ensure UI is updated with status data
                updateUI(data);
              });
          } else {
            updateUI(data);
            try {
              // OLSR Links
                if (data.links && data.links.length) {
                var linkTab = document.querySelector('#mainTabs a[href="#tab-olsr"]');
                if (linkTab) { if (window._uiDebug) console.debug('Showing OLSR tab with links from /status'); linkTab.parentElement.style.display = ''; }
                try { window._olsr_links = Array.isArray(data.links) ? data.links : []; } catch(e) { window._olsr_links = data.links || []; }
                populateOlsrLinksTable(window._olsr_links);
              } else {
                // Keep tab visible; it will lazy-load on click
                var linkTab = document.querySelector('#mainTabs a[href="#tab-olsr"]');
                if (linkTab) { if (window._uiDebug) console.debug('Keeping OLSR tab visible (no links yet)'); linkTab.parentElement.style.display = ''; }
              }
        // capture legacy olsrd_on flag if provided by backend full status later
        if (typeof status.olsrd_on === 'boolean') data.olsrd_on = status.olsrd_on;
              // Neighbors tab removed
            } catch(e){}
          }
          if (status.admin_url) {
            data.admin = { url: status.admin_url };
            updateUI(data);
            setLoginLink(status.admin_url);
          }
          // older code used status.admin_url; also support status.admin.url
          if (status.admin && status.admin.url) {
            data.admin = { url: status.admin.url };
            updateUI(data);
            setLoginLink(status.admin.url);
          }
          var nodedb = {};
          var nodedbReady = false;
          function tryRenderConnections() {
            if (!nodedbReady) return; // wait until nodedb loaded once
            return fetch('/connections.json',{cache:'no-store'}).then(function(r){ return r.json(); }).then(function(c){
              renderConnectionsTable(c, nodedb);
              var statusEl = document.getElementById('connections-status'); if(statusEl) statusEl.textContent = '';
            }).catch(function(e){ var el=document.getElementById('connections-status'); if(el) el.textContent='ERR: '+e; });
          }
          // load nodedb first then connections
          fetch('/nodedb.json',{cache:'no-store'}).then(function(r){ return r.json(); }).then(function(nb){ nodedb = nb || {}; nodedbReady = true; tryRenderConnections(); }).catch(function(){ nodedb = {}; nodedbReady = true; tryRenderConnections(); });
          function loadConnections() {
            // force refresh after nodedb already loaded
            if (!nodedbReady) return; // will auto-run when ready
            var statusEl = document.getElementById('connections-status'); if(statusEl) statusEl.textContent = 'Loading...';
            // Return a Promise so callers can finalize UI state
            return new Promise(function(resolve, reject){
              tryRenderConnections().then(function(){ if(statusEl) statusEl.textContent=''; resolve(); }).catch(function(err){ if(statusEl) statusEl.textContent='ERR: '+err; reject(err); });
            });
          }
          // defer loading connections and versions until tab activation to speed initial paint
          var _connectionsLoaded = false;
          var _versionsLoaded = false;
          // Versions tab removed; don't auto-load versions here (global header load happens elsewhere)
          function loadConnections() {
            if (_connectionsLoaded) return Promise.resolve();
            _connectionsLoaded = true;
            var statusEl = document.getElementById('connections-status'); if(statusEl) statusEl.textContent = 'Loading...';
            return fetch('/nodedb.json',{cache:'no-store'}).then(function(r){ return r.json(); }).then(function(nb){ var nodedb = nb || {}; return fetch('/connections.json',{cache:'no-store'}).then(function(r){ return r.json(); }).then(function(c){ renderConnectionsTable(c, nodedb); if(statusEl) statusEl.textContent=''; }).catch(function(e){ if(statusEl) statusEl.textContent='ERR: '+e; }); }).catch(function(){ if(statusEl) statusEl.textContent=''; });
          }
          function loadVersions() {
            if (_versionsLoaded) return Promise.resolve();
            _versionsLoaded = true;
            var statusEl = document.getElementById('versions-status'); if(statusEl) statusEl.textContent = 'Loading...';
            return fetch('/versions.json',{cache:'no-store'}).then(function(r){ return r.text(); }).then(function(txt){ try { var v = JSON.parse(txt); renderVersionsPanel(v); if(statusEl) statusEl.textContent = ''; } catch(e){ if(statusEl) statusEl.textContent='ERR: '+e; } }).catch(function(e){ var el=document.getElementById('versions-status'); if(el) el.textContent='ERR: '+e; });
          }
          document.getElementById('tr-run').addEventListener('click', function(){ runTraceroute(); });
          // Wire refresh buttons with consistent spinner + disable behavior
          var refreshConnBtn = document.getElementById('refresh-connections');
          if (refreshConnBtn) {
            refreshConnBtn.addEventListener('click', function(){
        try { refreshConnBtn.disabled = true; } catch(e){}
              // call loadConnections which returns a Promise
              try {
                var p = loadConnections();
                if (p && typeof p.finally === 'function') {
          p.finally(function(){ try{ refreshConnBtn.disabled=false; }catch(e){} });
                } else {
                  // Not a promise (nodedb not ready), just re-enable
          try{ refreshConnBtn.disabled=false; }catch(e){}
                }
              } catch(e){ try{ refreshConnBtn.disabled=false; }catch(e){} }
            });
          }
          var refreshVerBtn = document.getElementById('refresh-versions');
          if (refreshVerBtn) {
            refreshVerBtn.addEventListener('click', function(){
              try { refreshVerBtn.disabled = true; } catch(e){}
              // Always fetch fresh versions.json on manual refresh (force bypassing loadVersions cache)
              fetch('/versions.json', {cache:'no-store'}).then(function(r){ return r.text(); }).then(function(txt){ try { var v = JSON.parse(txt); renderVersionsPanel(v); } catch(e){} }).catch(function(e){ console.error('Failed to refresh versions:', e); }).finally(function(){ try{ refreshVerBtn.disabled=false; }catch(e){} });
            });
          }
          // render fixed traceroute-to-uplink results when provided by /status
          try {
            if (status.trace_to_uplink && Array.isArray(status.trace_to_uplink) && status.trace_to_uplink.length) {
              var trTab = document.querySelector('#mainTabs a[href="#tab-traceroute"]');
              if (trTab) trTab.parentElement.style.display = '';
              var hops = status.trace_to_uplink.map(function(h){ return { hop: h.hop || '', ip: h.ip || h.host || '', hostname: h.host || h.hostname || h.ip || '', ping: h.ping || '' }; });
              populateTracerouteTable(hops);
              var summaryEl = document.getElementById('traceroute-summary');
              if (summaryEl) summaryEl.textContent = 'Traceroute to ' + (status.trace_target || '') + ': ' + hops.length + ' hop(s)';
            }
          } catch(e) { /* ignore */ }
          // If backend provided a trace target but didn't include trace_to_uplink here,
          // ensure the traceroute input is populated and run once on initial load.
          try {
            if (!window._tracerouteAutoRunDone && status && status.trace_target && !(status.trace_to_uplink && status.trace_to_uplink.length)) {
              var trInput = document.getElementById('tr-host');
              if (trInput) {
                trInput.value = status.trace_target;
                window._tracerouteAutoRunDone = true;
                setTimeout(function(){ try { runTraceroute(); } catch(e){} }, 10);
              }
            }
          } catch(e) {}
        });
    });
  } catch(e) {
    // Fallback: try to load data without capabilities
    try {
      fetch('/status/lite', {cache: 'no-store'})
        .then(function(r) { return r.json(); })
        .then(function(status) {
          try { if (status.fetch_stats) populateFetchStats(status.fetch_stats); else populateFetchStats({}); } catch(e){}
          updateUI({
            hostname: status.hostname || 'Unknown',
            ip: status.ip || '',
            uptime: status.uptime_str || status.uptime || '',
            uptime_str: status.uptime_str || status.uptime || '',
            devices: status.devices || [],
            airos: status.airosdata || {},
            default_route: status.default_route || {},
            links: status.links || []
          });
          // Fallback traceroute initial display
          try {
            if (status.trace_to_uplink && Array.isArray(status.trace_to_uplink) && status.trace_to_uplink.length) {
              var trTab = document.querySelector('#mainTabs a[href="#tab-traceroute"]');
              if (trTab) trTab.parentElement.style.display = '';
              var hops = status.trace_to_uplink.map(function(h){ return { hop: h.hop || '', ip: h.ip || h.host || '', hostname: h.host || h.hostname || h.ip || '', ping: h.ping || '' }; });
              populateTracerouteTable(hops);
              var summaryEl = document.getElementById('traceroute-summary');
              if (summaryEl) summaryEl.textContent = 'Traceroute to ' + (status.trace_target || '') + ': ' + hops.length + ' hop(s)';
            }
          } catch(e) {}
        });
    } catch(e2) {}
  }
}

// Lazy load OLSR links when OLSR tab clicked first time
var _olsrLoaded = false;
window.addEventListener('load', function(){
  var mt = document.getElementById('mainTabs');
  if (!mt) return;
  // Automatically start traceroute with predefined traceroute_to destination at initial load
  ensureTraceroutePreloaded();
  function ensureTraceroutePreloaded(){
    try { console.log('ensureTraceroutePreloaded: start'); } catch(e){}
  var tbody = document.querySelector('#tracerouteTable tbody');
    // Always use dedicated traceroute endpoint which returns a clean JSON payload.
    fetch('/status/traceroute', {cache:'no-store'})
      .then(function(r){
        if (!r || !r.ok) throw new Error('traceroute endpoint unavailable');
        return r.json();
      })
      .then(function(st){
          var summaryEl = document.getElementById('traceroute-summary');
          // Only replace content when we actually have hops to show. This avoids
          // clearing a manually-run traceroute or recent results when /status
          // does not include traceroute data.
          if (st && st.trace_to_uplink && Array.isArray(st.trace_to_uplink) && st.trace_to_uplink.length) {
            var trTab = document.querySelector('#mainTabs a[href="#tab-traceroute"]');
            if (trTab) trTab.parentElement.style.display = '';
            var hops = st.trace_to_uplink.map(function(h){
              return {
                hop: h.hop || '',
                ip: h.ip || h.host || '',
                hostname: h.host || h.hostname || h.ip || '',
                ping: h.ping || ''
              };
            });
            populateTracerouteTable(hops);
            if (summaryEl) {
              summaryEl.textContent = 'Traceroute to ' + (st.trace_target || '') + ': ' + hops.length + ' hop(s)';
              summaryEl.setAttribute('aria-label', 'Traceroute summary: destination ' + (st.trace_target || '') + ', ' + hops.length + ' hops');
            }
          } else {
            // No precomputed hops available: only show a placeholder if the table
            // is currently empty (no manual run or previous data present).
            var hasRows = tbody && tbody.querySelectorAll && tbody.querySelectorAll('tr').length > 0;
            if (!hasRows) {
              if (tbody) {
                var tr = document.createElement('tr');
                var td = document.createElement('td');
                td.colSpan = 4;
                td.textContent = 'No traceroute data available.';
                tr.appendChild(td);
                tbody.appendChild(tr);
              }
              if (summaryEl) {
                summaryEl.textContent = 'Traceroute data not available.';
                summaryEl.setAttribute('aria-label', 'Traceroute summary: no data');
              }
            }
            try {
              if (!window._tracerouteAutoRunDone && st && st.trace_target) {
                var trInput = document.getElementById('tr-host');
                if (trInput) {
                  trInput.value = st.trace_target;
                  window._tracerouteAutoRunDone = true;
                  setTimeout(function(){ try { runTraceroute(); } catch(e){} }, 10);
                }
              }
            } catch(e) {}
          }
      })
      .catch(function(){
        // Treat any failure as 'no traceroute data' and keep UI quiet (no debug logs).
        var summaryEl = document.getElementById('traceroute-summary');
        if (tbody && !window._traceroutePopulatedAt) {
          var tr = document.createElement('tr');
          var td = document.createElement('td');
          td.colSpan = 4;
          td.textContent = 'No traceroute data available.';
          tr.appendChild(td);
          tbody.appendChild(tr);
        }
        if (summaryEl) {
          summaryEl.textContent = 'Traceroute data not available.';
          summaryEl.setAttribute('aria-label', 'Traceroute summary: no data');
        }
      });
  }
  mt.addEventListener('click', function(e){
    var a = e.target.closest('a'); if(!a) return;
    if (a.getAttribute('href') === '#tab-olsr' && !_olsrLoaded) {
  if (window._uiDebug) console.debug('OLSR tab clicked, lazy-loading /olsr/links');
      fetch('/olsr/links',{cache:'no-store'}).then(function(r){return r.json();}).then(function(o){
  if (window._uiDebug) console.debug('Received /olsr/links', o && (o.links? o.links.length : 'no links'));
        if (o.links && o.links.length) { populateOlsrLinksTable(o.links); }
        _olsrLoaded = true;
  }).catch(function(e){ if (window._uiDebug) console.debug('Failed to load /olsr/links', e); });
    } else if (a.getAttribute('href') === '#tab-traceroute') {
      ensureTraceroutePreloaded();
    } else if (a.getAttribute('href') === '#tab-log') {
      // lazy-load /log content
      if (window._logLoaded) return;
      var pre = document.getElementById('log-pre'); if (pre) pre.textContent = 'Loading...';
  fetch('/log?lines=100', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(obj){ try { var lines = obj && Array.isArray(obj.lines) ? obj.lines : []; renderLogArray(lines); window._logLoaded = true; } catch(e){ if (pre) pre.textContent = 'Error rendering log'; } }).catch(function(e){ if (pre) pre.textContent = 'Error loading /log: '+e; });
    }
  });
  // Refresh button support for OLSR Links
  var refreshLinksBtn = document.getElementById('refresh-links');
  if (refreshLinksBtn) {
    refreshLinksBtn.addEventListener('click', function(){
  // clear client-side cache to avoid mixing stale DOM rows with new data
  try { window._olsr_links = []; } catch(e) {}
  var statusEl = document.getElementById('links-status');
      try { refreshLinksBtn.disabled = true; } catch(e){}
  if (statusEl) statusEl.textContent = 'Refreshing…';
      // First force-update node_db (non-blocking by default). If server returns queued status
      // we proceed to fetch links immediately; if the client wants to ensure fresh names,
      // they can use ?wait=1 but that may block the UI.
      fetch('/nodedb/refresh',{cache:'no-store'}).then(function(r){ return r.json(); }).then(function(res){
        // If server indicated queued, we still continue to fetch links; the node_db
        // enrichment may arrive slightly later but UI remains responsive.
        return fetch('/olsr/links',{cache:'no-store'});
      }).then(function(r2){ return r2.json(); }).then(function(o){
        if (o.links && o.links.length) { 
          window._olsr_links = o.links.slice();
          populateOlsrLinksTable(o.links); 
        }
        if (statusEl) statusEl.textContent = '';
        _olsrLoaded = true;
        showActionToast('Links refreshed', 2500);
  }).catch(function(e){ if (statusEl) statusEl.textContent = 'ERR'; showActionToast('Error refreshing links', 4000); }).finally(function(){ try{ refreshLinksBtn.disabled=false; }catch(e){} });
    });
  }
});

// console polyfill for older browsers
if (!window.console) {
  window.console = {
    log: function() {},
    error: function() {},
    warn: function() {},
    info: function() {}
  };
}

// trim polyfill for older browsers
if (!String.prototype.trim) {
  String.prototype.trim = function() {
    return this.replace(/^\s+|\s+$/g, '');
  };
}

// forEach polyfill for older browsers
if (!Array.prototype.forEach) {
  Array.prototype.forEach = function(callback, thisArg) {
    for (var i = 0; i < this.length; i++) {
      callback.call(thisArg, this[i], i, this);
    }
  };
}

// Array.prototype.map polyfill for older browsers
if (!Array.prototype.map) {
  Array.prototype.map = function(callback, thisArg) {
    var result = [];
    for (var i = 0; i < this.length; i++) {
      result[i] = callback.call(thisArg, this[i], i, this);
    }
    return result;
  };
}

// classList polyfill for older browsers (avoids Illegal invocation by using a getter with element closure)
;(function(){
  var testEl = document && document.documentElement;
  if (!testEl) return;
  if (!('classList' in testEl)) {
    function trim(str){ return str.replace(/^\s+|\s+$/g,''); }
    function makeTokenList(el){
      function getClasses(){ return trim(el.className || '').split(/\s+/).filter(function(c){ return c.length; }); }
      return {
        add: function(token){
          if (!token) return;
            var classes = getClasses();
            if (classes.indexOf && classes.indexOf(token) === -1) { classes.push(token); }
            else if (!classes.indexOf) { // old browsers without indexOf
              var found = false; for (var i=0;i<classes.length;i++){ if(classes[i]===token){ found=true; break; } }
              if(!found) classes.push(token);
            }
            el.className = classes.join(' ');
        },
        remove: function(token){
          if (!token) return;
          var classes = getClasses();
          var out = [];
          for (var i=0;i<classes.length;i++){ if(classes[i]!==token) out.push(classes[i]); }
          el.className = out.join(' ');
        },
        contains: function(token){
          if (!token) return false;
          var classes = getClasses();
          if (classes.indexOf) return classes.indexOf(token) !== -1;
          for (var i=0;i<classes.length;i++){ if (classes[i]===token) return true; }
          return false;
        },
        toggle: function(token){ if (this.contains(token)) { this.remove(token); return false; } else { this.add(token); return true; } }
      };
    }
    try {
      Object.defineProperty(Element.prototype, 'classList', { get: function(){ return makeTokenList(this); } });
    } catch(e) { // fallback for very old browsers without defineProperty on DOM prototypes
      // Overwrite via simple function returning fresh object each time
      if (HTMLElement && HTMLElement.prototype) {
        HTMLElement.prototype.__getClassList = function(){ return makeTokenList(this); };
        HTMLElement.prototype.classList = makeTokenList(document.createElement('div')); // dummy to avoid errors
      }
    }
  }
})();

// querySelector and querySelectorAll polyfills for older browsers
if (!document.querySelector) {
  document.querySelector = function(selector) {
    if (selector.charAt(0) === '#') {
      return document.getElementById(selector.substring(1));
    }
    return document.getElementsByTagName(selector.substring(1))[0];
  };
}

if (!document.querySelectorAll) {
  document.querySelectorAll = function(selector) {
    if (selector.charAt(0) === '#') {
      var el = document.getElementById(selector.substring(1));
      return el ? [el] : [];
    }
    return document.getElementsByTagName(selector.substring(1));
  };
}

// addEventListener polyfill for older browsers
if (!document.addEventListener) {
  document.addEventListener = function(event, callback) {
    if (event === 'DOMContentLoaded') {
      if (document.readyState === 'complete' || document.readyState === 'interactive') {
        callback();
      } else {
        document.attachEvent('onreadystatechange', function() {
          if (document.readyState === 'complete') {
            callback();
          }
          // wire tab lazy-load for connections and versions
          var connTabLink = document.querySelector('#mainTabs a[href="#tab-connections"]');
          if (connTabLink) connTabLink.addEventListener('click', function(){ loadConnections(); });
          // Versions tab removed; no lazy-load handler needed
        });
      }
    } else {
      document.attachEvent('on' + event, callback);
    }
  };
}

document.addEventListener('DOMContentLoaded', function() {
  // Simple, reliable tab system
  const tabLinks = document.querySelectorAll('#mainTabs a');
  const tabPanes = document.querySelectorAll('.tab-pane');

  function showTab(targetId) {
    try { stopLinksPoll(); } catch(e) {}
    // Hide all panes
    tabPanes.forEach(pane => {
      pane.style.display = 'none';
      pane.classList.remove('active');
      // Don't add hidden class here to avoid conflicts
    });

    // Remove active class from all links
    tabLinks.forEach(link => {
      link.parentElement.classList.remove('active');
    });

    // Show target pane
    const targetPane = document.querySelector(targetId);
    if (targetPane) {
      targetPane.style.display = 'block';
      targetPane.classList.add('active');
      targetPane.classList.remove('hidden'); // Ensure hidden class is removed

      // Add active class to target link
      const targetLink = document.querySelector(`#mainTabs a[href="${targetId}"]`);
      if (targetLink) {
        targetLink.parentElement.classList.add('active');
      }

      // Debug logging
      console.log('Tab switched to:', targetId);
      console.log('Active pane:', targetPane.id, 'display:', targetPane.style.display, 'classes:', targetPane.className);

      // Load content for this tab
      onTabShown(targetId);
    } else {
      console.error('Target pane not found:', targetId);
    }
  }

  // Add click handlers
  tabLinks.forEach(link => {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      const targetId = this.getAttribute('href');
      showTab(targetId);
    });
  });

  // Ensure traceroute Run button is wired
  try {
    var runBtn = document.getElementById('tr-run');
    if (runBtn && !runBtn._wired) {
      runBtn.addEventListener('click', function(){ runTraceroute(); });
      runBtn._wired = true;
    }
  } catch(e) {}

  // Ensure the compact global versions header is populated early so the
  // sticky global header (outside of the Versions tab) is visible on first
  // paint. This is intentionally lightweight and marks a global flag to
  // avoid duplicate work when the Versions tab later lazy-loads.
  try {
    if (!window._versionsLoadedGlobal) {
      fetch('/versions.json', {cache: 'no-store'}).then(function(r){ return r.text(); }).then(function(txt){ try { var v = JSON.parse(txt); renderVersionsPanel(v); window._versionsLoadedGlobal = true; } catch(e) { console.error('Failed to load versions for header:', e); } }).catch(function(e){ console.error('Failed to fetch versions for header:', e); });
    }
  } catch(e) {}

  // Show initial active tab (only if not already visible)
  const initialActive = document.querySelector('#mainTabs li.active a');
  if (initialActive) {
    const initialTabId = initialActive.getAttribute('href');
    const initialPane = document.querySelector(initialTabId);
    if (initialPane && initialPane.style.display !== 'block') {
      showTab(initialTabId);
    } else {
      // Initial tab is already visible, just load its content
      onTabShown(initialTabId);
    }
  } else {
    // Fallback: show first tab
    showTab('#tab-main');
  }

  // Wire links_live controls (enable + interval)
  try {
    function renderLinksLiveControls() {
      var chk = document.getElementById('links-live-enable');
      var inp = document.getElementById('links-live-interval');
      if (!chk || !inp) return;
      try {
        var enabled = localStorage.getItem('links_live_enabled');
        var iv = localStorage.getItem('links_live_interval_s');
        if (enabled === null) enabled = '1';
        if (!iv) iv = String(Math.max(1, Math.floor(window._links_poll_interval_ms/1000) || 10));
        chk.checked = (String(enabled) === '1' || String(enabled) === 'true');
        inp.value = String(iv);
      } catch(e) { chk.checked = true; inp.value = String(Math.max(1, Math.floor(window._links_poll_interval_ms/1000) || 10)); }

      // change handlers
      chk.addEventListener('change', function(){
        try { localStorage.setItem('links_live_enabled', chk.checked ? '1' : '0'); } catch(e) {}
        try {
          if (chk.checked) startLinksPoll(); else stopLinksPoll();
        } catch(e) {}
      });
      inp.addEventListener('change', function(){
        try {
          var v = parseInt(inp.value,10);
          if (isNaN(v) || v < 1) v = 1;
          localStorage.setItem('links_live_interval_s', String(v));
          window._links_poll_interval_ms = v * 1000;
          // restart if running
          try { if (window._links_poll_handle) { stopLinksPoll(); startLinksPoll(); } } catch(e) {}
        } catch(e) {}
      });
    }
    try { renderLinksLiveControls(); } catch(e) {}
  } catch(e) {}

  // Clean up polling on unload
  window.addEventListener('beforeunload', function(){ try { stopLinksPoll(); stopLinksPoll(); } catch(e) {} });

  // ...existing code...

  // onTabShown: called whenever a tab becomes active
  function onTabShown(id) {
  try { if (window._uiDebug) { var pane = document.querySelector(id); if (pane) { var cs = window.getComputedStyle(pane); console.debug('onTabShown: id=', id, 'classes=', pane.className, 'computedDisplay=', cs.display, 'visible=', cs.display!=='none'); } } } catch(e){}
    console.log('Loading content for tab:', id);
    try {
      if (id === '#tab-log') {
        // if log not yet loaded, auto-refresh
        if (!window._logLoaded) refreshLog();
        // if already loaded and large, ensure virtualization is enabled
        try { if ((window._log_cache && window._log_cache.lines && window._log_cache.lines.length > 500) && !window._log_virtual_enabled) { enableVirtualLogs(); } } catch(e) {}
      }
      // Ensure other tabs lazy-load reliably even if some listeners didn't attach
      if (id === '#tab-main') {
        console.log('Main tab has static content');
        setTabLoaded('tab-main');
        // Load status data to populate main-host if not already loaded
        try {
          if (!window._statusLoaded || (Date.now() - (window._statusLoadedAt || 0) > 10000)) {
            safeFetchStatus({cache:'no-store'}).then(function(st){ try { if (st) { updateUI(st); } window._statusLoaded = true; window._statusLoadedAt = Date.now(); } catch(e){} }).catch(function(){});
          }
        } catch(e) {}
      }
      if (id === '#tab-contact') {
        // Contact tab has static content, ensure it's visible
        console.log('Contact tab has static content');
        setTabLoaded('tab-contact');
        try {
          var contactPane = document.getElementById('tab-contact');
          if (contactPane) {
            contactPane.style.display = 'block';
          }
        } catch(e) {}
      }
      if (id === '#tab-status') {
        // fetch full status and populate UI if not already loaded recently
        console.log('Loading status tab content...');
        setTabLoading('tab-status');
        try {
            if (!window._statusLoaded || (Date.now() - (window._statusLoadedAt || 0) > 10000)) {
            console.log('Fetching /status/lite API...');
            safeFetchStatus({cache:'no-store'}).then(function(st){ try { if (st) { console.log('Status data received:', Object.keys(st)); updateUI(st); if (st.links && Array.isArray(st.links) && st.links.length) { try { window._olsr_links = st.links.slice(); populateOlsrLinksTable(window._olsr_links); } catch(e){} } } window._statusLoaded = true; window._statusLoadedAt = Date.now(); setTabLoaded('tab-status'); } catch(e){ setTabError('tab-status'); } }).catch(function(){ setTabError('tab-status'); });
          } else {
            console.log('Status already loaded recently');
            setTabLoaded('tab-status');
          }
          // links_live continuous polling removed: we perform a one-off refresh
          // when the user opens the OLSR Links tab instead.
        } catch(e) { setTabError('tab-status'); }
      }
      if (id === '#tab-stats') {
        console.log('Loading statistics tab content...');
        setTabLoading('tab-stats');
        try {
          // Initialize Chart.js charts if not already done
          if (!window._charts || !window._charts.network) {
            initStatsCharts();
          }
          // Start stats polling if not already running
          _startStatsPoll();
          setTabLoaded('tab-stats');
        } catch(e) {
          console.error('Failed to initialize stats tab:', e);
          setTabError('tab-stats');
        }
      }
      if (id === '#tab-olsr') {
        console.log('Loading OLSR links tab content...');
        setTabLoading('tab-olsr');
        try {
          // If we haven't loaded yet, or the table is present but empty, fetch and populate.
          var olsrtbody = document.querySelector('#olsrLinksTable tbody');
          var needFetch = !window._olsrLoaded || !olsrtbody || (olsrtbody && olsrtbody.querySelectorAll('tr').length === 0);
          console.log('OLSR tab - needFetch:', needFetch, 'tbody exists:', !!olsrtbody, 'current rows:', olsrtbody ? olsrtbody.querySelectorAll('tr').length : 0);
          if (needFetch) {
            try { if (olsrtbody) { clearChildren(olsrtbody); var tr=document.createElement('tr'); var td=document.createElement('td'); td.colSpan=12; td.className='text-muted'; td.textContent='Loading…'; tr.appendChild(td); olsrtbody.appendChild(tr); } } catch(e){}
            // Fetch status to populate OLSR links
            safeFetchStatus({cache:'no-store'}).then(function(st){
              try {
                if (st && st.links && Array.isArray(st.links) && st.links.length) {
                  try { window._olsr_links = st.links.slice(); populateOlsrLinksTable(window._olsr_links); } catch(e){}
                }
                window._olsrLoaded = true;
                setTabLoaded('tab-olsr');
                try {
                  fetch('/status/links_live', {cache:'no-store'}).then(function(r){ if(!r||!r.ok) throw new Error('HTTP '+(r&&r.status)); return r.json(); }).then(function(obj){ try { if (obj && obj.links && Array.isArray(obj.links)) { window._olsr_links = obj.links.slice(); populateOlsrLinksTable(window._olsr_links); } } catch(e){} }).catch(function(){ /* ignore */ });
                } catch(e) {}
              } catch(e) { setTabError('tab-olsr'); }
            }).catch(function(){ setTabError('tab-olsr'); });
          } else {
            console.log('OLSR links already loaded');
            setTabLoaded('tab-olsr');
            try {
              fetch('/status/links_live', {cache:'no-store'}).then(function(r){ if(!r||!r.ok) throw new Error('HTTP '+(r&&r.status)); return r.json(); }).then(function(obj){ try { if (obj && obj.links && Array.isArray(obj.links)) { window._olsr_links = obj.links.slice(); populateOlsrLinksTable(window._olsr_links); } } catch(e){} }).catch(function(){ /* ignore */ });
            } catch(e) {}
          }
        } catch(e) { setTabError('tab-olsr'); }
      }
      if (id === '#tab-olsr2') {
        console.log('Loading OLSR2 links tab content...');
        setTabLoading('tab-olsr2');
        try {
          // Fetch status to populate OLSR2 data
          safeFetchStatus({cache:'no-store'}).then(function(st){
            try {
              if (st && st.olsr2_on) {
                populateOlsr2Tab(st);
              }
              setTabLoaded('tab-olsr2');
            } catch(e) { setTabError('tab-olsr2'); }
          }).catch(function(){ setTabError('tab-olsr2'); });
        } catch(e) { setTabError('tab-olsr2'); }
      }
      if (id === '#tab-connections') {
        console.log('Loading connections tab content...');
        setTabLoading('tab-connections');
        try {
          if (!window._connectionsLoadedGlobal) {
            console.log('Fetching connections APIs...');
            Promise.all([ fetch('/nodedb.json', {cache:'no-store'}).then(function(r){return r.json();}).catch(function(){return {}; }), fetch('/connections.json', {cache:'no-store'}).then(function(r){return r.json();}).catch(function(){return {}; }) ]).then(function(results){ try { var ndb = results[0] || {}; var con = results[1] || {}; console.log('Connections data received - nodedb keys:', Object.keys(ndb).length, 'connections:', Array.isArray(con) ? con.length : 'not array'); renderConnectionsTable(con, ndb); window._connectionsLoadedGlobal = true; setTabLoaded('tab-connections'); } catch(e){ setTabError('tab-connections'); } }).catch(function(){
              // Show fallback content when API fails
              console.error('Failed to fetch connections data');
              var tbody = document.querySelector('#connectionsTable tbody');
              if (tbody) {
                clearChildren(tbody); var tr=document.createElement('tr'); var td=document.createElement('td'); td.colSpan=6; td.className='text-muted'; td.textContent='No connection data available. This tab requires backend API access.'; tr.appendChild(td); tbody.appendChild(tr);
              }
              setTabError('tab-connections');
            });
          } else {
            console.log('Connections already loaded');
            setTabLoaded('tab-connections');
          }
        } catch(e) { setTabError('tab-connections'); }
      }
      // Versions tab removed - no action needed here
      if (id === '#tab-traceroute') {
        try {
          // Use the dedicated traceroute endpoint which returns a clean JSON payload
          // and avoid fetching /status here because /status may omit trace_to_uplink
          // and would otherwise overwrite a valid traceroute table.
          fetch('/status/traceroute', {cache:'no-store'})
            .then(function(r){ if (!r || !r.ok) throw new Error('traceroute endpoint unavailable'); return r.json(); })
            .then(function(st){
              try {
                if (st && st.trace_to_uplink && Array.isArray(st.trace_to_uplink) && st.trace_to_uplink.length) {
                  var hops = st.trace_to_uplink.map(function(h){ return { hop: h.hop || '', ip: h.ip || h.host || '', hostname: h.host || h.hostname || h.ip || '', ping: h.ping || '' }; });
                  populateTracerouteTable(hops);
                  return;
                }
                // If server provided only a trace_target (no precomputed hops), populate input and maybe auto-run
                if (st && st.trace_target && !(st.trace_to_uplink && st.trace_to_uplink.length)) {
                  try {
                    var trInput = document.getElementById('tr-host');
                    if (trInput) {
                      trInput.value = st.trace_target;
                      if (!window._traceroutePopulatedAt && !window._tracerouteAutoRunDone) {
                        window._tracerouteAutoRunDone = true;
                        setTimeout(function(){ try { runTraceroute(); } catch(e){} }, 10);
                      }
                    }
                  } catch(e) {}
                }
              } catch(e) { /* ignore per-tab errors */ }
            }).catch(function(){
              // Only show fallback content if traceroute table is empty to avoid
              // clobbering results populated by a recent /status/traceroute or manual run.
              var tbody = document.querySelector('#tracerouteTable tbody');
              var hasRows = tbody && tbody.querySelectorAll && tbody.querySelectorAll('tr').length > 0;
              if (!hasRows) {
                if (tbody) {
                  tbody.innerHTML = ''; var tr=document.createElement('tr'); var td=document.createElement('td'); td.colSpan=4; td.className='text-muted'; td.textContent='Traceroute data not available. This tab requires backend API access.'; tr.appendChild(td); tbody.appendChild(tr);
                }
              }
            });
        } catch(e) {}
      }
      if (id === '#tab-neighbors') {
        try {
          // Show fallback content for neighbors tab
          var tbody = document.querySelector('#neighborsTable tbody');
          if (tbody && tbody.querySelectorAll('tr').length === 0) {
            tbody.innerHTML = ''; var tr=document.createElement('tr'); var td=document.createElement('td'); td.colSpan=7; td.className='text-muted'; td.textContent='Neighbor data not available. This tab requires a running OLSR daemon.'; tr.appendChild(td); tbody.appendChild(tr);
          }
        } catch(e) {}
      }
    } catch(e) {}
  }

  // Try to detect platform-specific endpoints and perform any platform-specific
  // initialization. This was previously missing and caused a runtime error.
  function detectPlatformAndLoad() {
    try {
      // Simple heuristic: if /platform.json exists, fetch it to learn capabilities
      fetch('/platform.json', {cache:'no-store'}).then(function(r){ if(!r || !r.ok) return; return r.json(); }).then(function(p){
        try {
          window._platform_info = p || {};
          // if a platform-specific loader exists globally (e.g. loadForUbiquiti), call it
          if (window.loadForPlatform && typeof window.loadForPlatform === 'function') {
            try { window.loadForPlatform(window._platform_info); } catch(e){}
          }
        } catch(e){}
      }).catch(function(){ /* ignore - no platform.json available */ });
    } catch(e){}
  }
  detectPlatformAndLoad();
  try { _startStatsPoll(); } catch(e) {}
  // Badge interactivity: clicking a badge forces a stats refresh and shows timestamp
  function _setBadgeInteractive(){
    try {
      var bn = document.getElementById('badge-nodes'); var br = document.getElementById('badge-routes');
      function setClick(el){ if(!el) return; if(el._wired) return; el.style.cursor='pointer'; el.addEventListener('click', function(){ try { el.textContent = el.textContent + ' • refreshing…'; fetch('/status/stats', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(s){ try { if (s && typeof s.olsr_nodes_count !== 'undefined') { var n = document.getElementById('badge-nodes'); if(n) n.textContent = 'Nodes: '+String(s.olsr_nodes_count); } if (s && typeof s.olsr_routes_count !== 'undefined') { var rEl = document.getElementById('badge-routes'); if(rEl) rEl.textContent = 'Routes: '+String(s.olsr_routes_count); } var now = new Date(); el.title = 'Last refreshed: ' + now.toLocaleString(); }catch(e){} }).catch(function(){ /* ignore */ }); } catch(e){} }); el._wired = true; }
      setClick(bn); setClick(br);
    } catch(e) {}
  }
  // wire badge interactivity once DOM ready
  document.addEventListener('DOMContentLoaded', function(){ try{ _setBadgeInteractive(); }catch(e){} });

  // Dropdown: toggle and content population
  function _wireStatusDropdown(){
    try {
      var wrap = document.getElementById('status-dropdown-wrap'); if (!wrap) return;
      var badges = document.getElementById('status-badges'); var menu = document.getElementById('status-dropdown-menu'); var details = document.getElementById('status-details'); var ts = document.getElementById('status-dropdown-ts'); var refresh = document.getElementById('status-dropdown-refresh');
      function closeMenu(){ if (!menu) return; menu.setAttribute('aria-hidden','true'); }
      function openMenu(){ if (!menu) return; menu.setAttribute('aria-hidden','false'); }
      // toggle on badge click
      if (badges && !badges._wired) {
        badges.addEventListener('click', function(){ try { if (menu && menu.getAttribute('aria-hidden') === 'false') { closeMenu(); } else { openMenu(); _populateDropdown(); } } catch(e){} }); badges._wired = true; }
      // close when clicking outside
      document.addEventListener('click', function(e){ try { if (!wrap.contains(e.target)) { closeMenu(); } } catch(e){} });
      if (refresh) refresh.addEventListener('click', function(){ _populateDropdown(); });
      function applyThresholds(s){
        try {
          var thresholds = (s && s.thresholds) ? s.thresholds : {};
          var q_warn = thresholds.queue_warn || 50; var q_crit = thresholds.queue_crit || 200;
          // nodes / routes threshold examples: user may provide nodes_warn/nodes_crit
          var n_warn = thresholds.nodes_warn || 100; var n_crit = thresholds.nodes_crit || 10; // default: low nodes critical
          var r_warn = thresholds.routes_warn || 200; var r_crit = thresholds.routes_crit || 1000;
          var bn = document.getElementById('badge-nodes'); var br = document.getElementById('badge-routes');
          if (bn && typeof s.olsr_nodes_count !== 'undefined') {
            var n = Number(s.olsr_nodes_count) || 0; bn.classList.remove('warn','crit'); if (n <= n_crit) bn.classList.add('crit'); else if (n <= n_warn) bn.classList.add('warn');
          }
          if (br && typeof s.olsr_routes_count !== 'undefined') {
            var r = Number(s.olsr_routes_count) || 0; br.classList.remove('warn','crit'); if (r >= r_crit) br.classList.add('crit'); else if (r >= r_warn) br.classList.add('warn');
          }
        } catch(e) {}
      }
      // populate dropdown content
      function _populateDropdown(){
        if (!details) return;
        details.textContent = 'Loading…';
        fetch('/status/stats', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(s){ try {
            // Use the reusable card renderer to render dropdown details
            try {
              renderCard({
                container: details,
                title: '',
                panelClass: 'panel panel-default',
                bodyStyle: 'padding:8px',
                render: function(body, headerRight) {
                  // top badges for nodes/routes
                  var top = document.createElement('div'); top.style.display = 'flex'; top.style.gap = '8px'; top.style.alignItems = 'center';
                  var nodesCount = (typeof s.olsr_nodes_count !== 'undefined') ? s.olsr_nodes_count : '-';
                  var routesCount = (typeof s.olsr_routes_count !== 'undefined') ? s.olsr_routes_count : '-';
                  var bn = document.createElement('div'); bn.className = 'metric-badge'; bn.textContent = 'Nodes: ' + String(nodesCount); top.appendChild(bn);
                  var br = document.createElement('div'); br.className = 'metric-badge'; br.textContent = 'Routes: ' + String(routesCount); top.appendChild(br);
                  body.appendChild(top);

                  // Fetch queue section
                  if (s.fetch_stats) {
                    var sep = document.createElement('div'); sep.style.marginTop = '8px'; sep.style.fontWeight = '600'; sep.textContent = 'Fetch Queue'; body.appendChild(sep);
                    var qwrap = document.createElement('div'); qwrap.style.marginTop = '6px';
                    function val(name, alt){ return s.fetch_stats[name] || s.fetch_stats[alt] || 0; }
                    var queued = val('queued_count','queue_length') || val('queued','queue_len');
                    var processing = val('processing_count','in_progress') || val('processing');
                    var dropped = val('dropped_count','dropped') || val('dropped');
                    var queuedDiv = document.createElement('div'); queuedDiv.textContent = 'Queued: ' + String(queued); qwrap.appendChild(queuedDiv);
                    var procDiv = document.createElement('div'); procDiv.textContent = 'Processing: ' + String(processing); qwrap.appendChild(procDiv);
                    var dropDiv = document.createElement('div'); dropDiv.textContent = 'Dropped: ' + String(dropped); qwrap.appendChild(dropDiv);
                    body.appendChild(qwrap);
                  }
                }
              });
            } catch(e) {
              details.textContent = 'Error rendering details';
            }

            if (ts) { var now = new Date(); ts.textContent = now.toLocaleTimeString(); ts.title = now.toString(); }
            applyThresholds(s);
          } catch(e){ details.textContent = 'Error rendering details'; } }).catch(function(){ details.textContent = 'Error fetching stats'; });
      }
    } catch(e) {}
  }
  document.addEventListener('DOMContentLoaded', function(){ try{ _wireStatusDropdown(); }catch(e){} });
  // ...existing code...
});

// --- Log tab helpers ---
function parseLogLine(line) {
  // naive parse: try to extract timestamp and level prefix like "2025-09-09 12:00:00 [INFO] ..."
  try {
    var m = line.match(/^\s*(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s*(?:\[([^\]]+)\])?\s*(.*)$/);
    if (m) return { ts: m[1], level: (m[2]||'').toUpperCase(), msg: m[3] };
  } catch(e) {}
  return { ts: '', level: '', msg: line };
}

// Render log lines (paginated). Expects an array of lines (strings) in data.lines
window._log_cache = window._log_cache || { lines: [], filtered: [], page: 0, pageSize: 20 };
function renderLogPage() {
  var tbody = document.getElementById('log-tbody'); if (!tbody) return;
  var pagerWrap = document.getElementById('log-pager');
  var cache = window._log_cache; var lines = cache.filtered.length ? cache.filtered : cache.lines;
  var total = lines.length || 0;
  var pages = Math.max(1, Math.ceil(total / cache.pageSize));
  if (cache.page >= pages) cache.page = pages - 1;
  var start = cache.page * cache.pageSize; var end = Math.min(total, start + cache.pageSize);
  var slice = lines.slice(start, end);
  // render rows into tbody
  tbody.innerHTML = '';
  if (!slice.length) {
    var tr = document.createElement('tr'); var td = document.createElement('td'); td.colSpan = 3; td.className = 'text-muted'; td.style.padding = '12px'; td.textContent = '(no log lines)'; tr.appendChild(td); tbody.appendChild(tr);
  } else {
    slice.forEach(function(ln){ var p = parseLogLine(ln); var tr = document.createElement('tr'); var tdTs = document.createElement('td'); tdTs.style.color='#666'; tdTs.style.fontSize='11px'; tdTs.textContent = p.ts || ''; var tdLevel = document.createElement('td'); tdLevel.style.fontWeight='600'; tdLevel.textContent = p.level || ''; if (p.level==='ERROR' || p.level==='ERR' || p.level==='CRITICAL') tdLevel.style.color='#a94442'; else if (p.level==='WARN' || p.level==='WARNING') tdLevel.style.color='#8a6d3b'; else if (p.level==='INFO') tdLevel.style.color='#31708f'; else if (p.level==='DEBUG') tdLevel.style.color='#3a3a3a'; var tdMsg = document.createElement('td'); tdMsg.style.whiteSpace='pre-wrap'; tdMsg.textContent = p.msg || ''; tr.appendChild(tdTs); tr.appendChild(tdLevel); tr.appendChild(tdMsg); tbody.appendChild(tr); });
  }
  // pager html
  if (pagerWrap) {
    pagerWrap.innerHTML = '';
    var info = document.createElement('div'); info.textContent = 'Showing '+(start+1)+'-'+(end)+' of '+total+' entries';
    var controls = document.createElement('div'); controls.style.display='inline-block'; controls.style.marginLeft='12px';
    var prev = document.createElement('button'); prev.id='log-prev'; prev.className='btn btn-xs btn-default'; prev.textContent='Prev'; if (cache.page===0) prev.disabled=true;
    var span = document.createElement('span'); span.style.margin='0 6px'; span.textContent = 'Page '+(cache.page+1)+'/'+pages;
    var next = document.createElement('button'); next.id='log-next'; next.className='btn btn-xs btn-default'; next.textContent='Next'; if (cache.page+1>=pages) next.disabled=true;
    controls.appendChild(prev); controls.appendChild(span); controls.appendChild(next);
    pagerWrap.appendChild(info); pagerWrap.appendChild(controls);
    // wire buttons
    try { prev.addEventListener('click', function(){ if (window._log_cache.page>0) { window._log_cache.page--; renderLogPage(); } }); next.addEventListener('click', function(){ if ((window._log_cache.page+1)*window._log_cache.pageSize < (window._log_cache.filtered.length || window._log_cache.lines.length)) { window._log_cache.page++; renderLogPage(); } }); } catch(e){}
  }
  // Ensure log tab pane is visible after rendering
  try { var pane = document.getElementById('tab-log'); if (pane) { pane.classList.remove('hidden'); pane.style.display = ''; } } catch(e){}
}

function renderLogArray(lines) {
  window._log_cache.lines = Array.isArray(lines) ? lines.slice().reverse() : [];
  window._log_cache.filtered = [];
  window._log_cache.page = 0;
  var container = document.getElementById('log-table-wrap');
  if (!container) {
    // fallback: show log lines in log-pre if table container is missing
    var pre = document.getElementById('log-pre');
    if (pre) {
      pre.textContent = lines.length ? lines.join('\n') : '(no log lines)';
    }
    return;
  }
  // If logs are large, enable virtualized rendering for CPU/memory efficiency
  try {
    var len = window._log_cache.lines.length || 0;
    var threshold = 500;
    if (len > threshold) {
      enableVirtualLogs();
      virtualRender();
      try { var pager = document.getElementById('log-pager'); if (pager) pager.innerHTML = ''; } catch(e) {}
      return;
    }
  } catch(e) {}
  disableVirtualLogs();
  renderLogPage();
}

// --- Virtualized log table helpers (lightweight) ---
function enableVirtualLogs() {
  if (window._log_virtual_enabled) return;
  var container = document.getElementById('log-table-wrap');
  if (!container) return;
  window._log_virtual_enabled = true;
  // render using renderCard for consistent header/body
  try {
    renderCard({
      container: container,
      panelClass: 'panel panel-default',
      title: 'Log (virtualized)',
      bodyStyle: 'padding:8px; overflow:auto; height:400px',
      render: function(body, headerRight) {
        // create table skeleton inside body
        var table = document.createElement('table');
        table.className = 'table table-condensed';
        table.id = 'log-table-virtual';
  var thead = document.createElement('thead');
  var trh = document.createElement('tr');
  var th1 = document.createElement('th'); th1.style.width = '160px'; th1.textContent = 'Timestamp';
  var th2 = document.createElement('th'); th2.style.width = '100px'; th2.textContent = 'Level';
  var th3 = document.createElement('th'); th3.textContent = 'Message';
  trh.appendChild(th1); trh.appendChild(th2); trh.appendChild(th3); thead.appendChild(trh);
        table.appendChild(thead);
        var tbody = document.createElement('tbody');
        tbody.id = 'log-virtual-tbody';
        tbody.style.position = 'relative';
        table.appendChild(tbody);

        // spacer to emulate full height
        var spacer = document.createElement('div');
        spacer.id = 'log-virtual-spacer';
        spacer.style.width = '1px';
        spacer.style.height = '0px';

        body.appendChild(table);
        body.appendChild(spacer);
        // forward scroll events from body
        body.addEventListener('scroll', virtualScrollHandler);
      }
    });
  } catch(e) { container.innerHTML = ''; }
}

function disableVirtualLogs() {
  if (!window._log_virtual_enabled) return;
  var container = document.getElementById('log-table-wrap');
  if (!container) return;
  window._log_virtual_enabled = false;
  try { body = document.getElementById('log-table-wrap'); if (body) body.removeEventListener('scroll', virtualScrollHandler); } catch(e) {}
  // restore basic table using renderCard
  try {
    renderCard({
      container: container,
      panelClass: 'panel panel-default',
      title: 'Log',
      bodyStyle: 'padding:8px',
      render: function(body) {
        var table = document.createElement('table');
        table.className = 'table table-condensed';
        table.id = 'log-table';
  var thead = document.createElement('thead'); var trh=document.createElement('tr'); var thh1=document.createElement('th'); thh1.style.width='160px'; thh1.textContent='Timestamp'; var thh2=document.createElement('th'); thh2.style.width='100px'; thh2.textContent='Level'; var thh3=document.createElement('th'); thh3.textContent='Message'; trh.appendChild(thh1); trh.appendChild(thh2); trh.appendChild(thh3); thead.appendChild(trh);
  var tbodyInner = document.createElement('tbody'); tbodyInner.id = 'log-tbody'; var tr = document.createElement('tr'); var tdEmpty = document.createElement('td'); tdEmpty.colSpan = 3; tdEmpty.className = 'text-muted'; tdEmpty.style.padding = '12px'; tdEmpty.textContent = '(no log lines)'; tr.appendChild(tdEmpty); tbodyInner.appendChild(tr);
  table.appendChild(thead); table.appendChild(tbodyInner);
        body.appendChild(table);
      }
    });
  } catch(e) { container.innerHTML = ''; }
}

function virtualScrollHandler() {
  if (window._log_virtual_raf) return;
  window._log_virtual_raf = requestAnimationFrame(function(){ window._log_virtual_raf = null; virtualRender(); });
}

function virtualRender() {
  var container = document.getElementById('log-table-wrap');
  var spacer = document.getElementById('log-virtual-spacer');
  var tbody = document.getElementById('log-virtual-tbody');
  if (!container || !spacer || !tbody) return;
  var lines = (window._log_cache && window._log_cache.lines) ? window._log_cache.lines : [];
  var total = lines.length;
  var rowHeight = 26; // estimated row height in px
  spacer.style.height = (total * rowHeight) + 'px';
  var scrollTop = container.scrollTop || 0;
  var viewportHeight = container.clientHeight || 400;
  var firstIdx = Math.max(0, Math.floor(scrollTop / rowHeight) - 5);
  var visibleCount = Math.ceil(viewportHeight / rowHeight) + 10;
  var lastIdx = Math.min(total, firstIdx + visibleCount);
  // position tbody
  tbody.style.transform = 'translateY(' + (firstIdx * rowHeight) + 'px)';
  // render visible rows
  tbody.innerHTML = '';
  for (var i = firstIdx; i < lastIdx; i++) {
    var ln = lines[i] || '';
    var p = parseLogLine(ln);
    var tr = document.createElement('tr');
    var tdTs = document.createElement('td'); tdTs.style.color='#666'; tdTs.style.fontSize='11px'; tdTs.textContent = p.ts || '';
    var tdLevel = document.createElement('td'); tdLevel.style.fontWeight='600'; tdLevel.textContent = p.level || '';
    if (p.level==='ERROR' || p.level==='ERR' || p.level==='CRITICAL') tdLevel.style.color='#a94442'; else if (p.level==='WARN' || p.level==='WARNING') tdLevel.style.color='#8a6d3b'; else if (p.level==='INFO') tdLevel.style.color='#31708f'; else if (p.level==='DEBUG') tdLevel.style.color='#3a3a3a';
    var tdMsg = document.createElement('td'); tdMsg.style.whiteSpace='pre-wrap'; tdMsg.textContent = p.msg || '';
    tr.appendChild(tdTs); tr.appendChild(tdLevel); tr.appendChild(tdMsg);
    tbody.appendChild(tr);
  }
}

function refreshLog() {
  var btn = document.getElementById('refresh-log');
  var classBtns = document.querySelectorAll('.refresh-log-btn');
  var status = document.getElementById('log-status');
  try {
    if (btn) btn.disabled = true;
    if (classBtns && classBtns.length) classBtns.forEach(function(b){ b.disabled = true; });
    if (status) status.textContent = 'Refreshing...';
  } catch(e){}
  // Request all available log lines; backend will limit automatically
  fetch('/log', {cache:'no-store'})
    .then(function(r){ return r.json(); })
    .then(function(obj){
      try {
        // Accept both array and object responses from backend
        var arr = [];
        if (Array.isArray(obj)) {
          arr = obj;
        } else if (obj && Array.isArray(obj.lines)) {
          arr = obj.lines;
        } else if (obj && typeof obj === 'object' && Object.keys(obj).length > 0) {
          // If backend returns an object with numbered keys (log lines)
          arr = Object.values(obj);
        }
        renderLogArray(arr);
        window._logLoaded = true;
        if (status) status.textContent = '';
      } catch(e) {
        var tbody = document.getElementById('log-tbody');
        if (tbody) { clearChildren(tbody); var tr=document.createElement('tr'); var td=document.createElement('td'); td.colSpan=3; td.className='text-danger'; td.textContent='Error rendering log'; tr.appendChild(td); tbody.appendChild(tr); }
        if (status) status.textContent = 'Error';
      }
    })
    .catch(function(e){
      var tbody = document.getElementById('log-tbody');
  if (tbody) { clearChildren(tbody); var tr=document.createElement('tr'); var td=document.createElement('td'); td.colSpan=3; td.className='text-danger'; td.textContent='Error loading /log: ' + escapeHtml(String(e)); tr.appendChild(td); tbody.appendChild(tr); }
      if (status) status.textContent = 'Error';
    })
    .finally(function(){
      try {
        if (btn) btn.disabled = false;
        if (classBtns && classBtns.length) classBtns.forEach(function(b){ b.disabled = false; });
      } catch(e){}
    });
}

// escape HTML simple helper
function escapeHtml(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

// wire refresh button on load
window.addEventListener('load', function(){
  // support both legacy ID and new class for refresh buttons
  try {
    var r = document.getElementById('refresh-log'); if (r) r.addEventListener('click', function(){ refreshLog(); });
  } catch(e){}
  try {
    var r2 = document.querySelectorAll('.refresh-log-btn'); if (r2 && r2.length) { r2.forEach(function(b){ b.addEventListener('click', function(){ refreshLog(); }); }); }
  } catch(e){}
  var f = document.getElementById('log-filter'); if (f) { f.addEventListener('keydown', function(e){ if (e.key === 'Enter') { e.preventDefault(); refreshLog(); } }); }
});
// filter wiring
document.addEventListener('DOMContentLoaded', function(){ var f = document.getElementById('log-filter'); if (!f) return; f.addEventListener('input', function(){ var q = (f.value||'').trim().toLowerCase(); if (!q) { window._log_cache.filtered = []; window._log_cache.page = 0; renderLogPage(); return; } var lines = window._log_cache.lines || []; window._log_cache.filtered = lines.filter(function(l){ return l.toLowerCase().indexOf(q) !== -1; }); window._log_cache.page = 0; renderLogPage(); }); });

// Enable simple client-side sorting for tables whose TH elements contain a data-key attribute
function enableTableSorting() {
  function sortTable(table, colIndex, asc) {
    var tbody = table.tBodies[0]; if (!tbody) return;
    var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
    rows.sort(function(a,b){
      var ta = (a.children[colIndex] && a.children[colIndex].textContent) ? a.children[colIndex].textContent.trim() : '';
      var tb = (b.children[colIndex] && b.children[colIndex].textContent) ? b.children[colIndex].textContent.trim() : '';
      // try numeric compare
      var na = parseFloat(ta.replace(/[^0-9\-\.]/g, ''));
      var nb = parseFloat(tb.replace(/[^0-9\-\.]/g, ''));
      if (!isNaN(na) && !isNaN(nb)) {
        return asc ? na - nb : nb - na;
      }
      // fallback: localeCompare
      return asc ? ta.localeCompare(tb) : tb.localeCompare(ta);
    });
    // re-append rows
    rows.forEach(function(r){ tbody.appendChild(r); });
  }

  var tables = document.querySelectorAll('table');
  tables.forEach(function(table){
    var ths = table.querySelectorAll('th');
    ths.forEach(function(th, idx){
      if (th.getAttribute('data-key')) {
        th.style.cursor = 'pointer';
        var asc = true;
        th.addEventListener('click', function(){
          sortTable(table, idx, asc);
          // toggle asc/desc and show a simple mark
          var mark = th.querySelector('.sort-mark');
          if (!mark) { mark = document.createElement('span'); mark.className='sort-mark'; th.appendChild(mark); }
          mark.textContent = asc ? ' ▲' : ' ▼';
          asc = !asc;
        });
      }
    });
  });
}

// initialize sorting behaviors early
try { enableTableSorting(); } catch(e) {}

// Populate dynamic nav entries (host + login) after status load
function populateNavHost(host, ip) {
  var el = document.getElementById('nav-host');
  if (!el) return;
  // Ensure the nav shows "IP - hostname". Preserve any icon markup if present.
  try {
    var hostnameSpan = el.querySelector('#hostname');
    // detect an existing icon (a glyphicon inside a wrapper span)
    var iconElem = el.querySelector('.glyphicon');
    var iconHtml = '';
    if (iconElem) {
      // prefer the immediate parent so we keep styling wrappers
      if (iconElem.parentNode && iconElem.parentNode.outerHTML) iconHtml = iconElem.parentNode.outerHTML; else iconHtml = iconElem.outerHTML || '';
    }
    // Show IP then hostname; if the hostname contains the literal token 'nodename'
    // try to replace it with the real nodename from the cached nodedb (if available).
    var ipPart = (ip ? ip : '');
    var displayHost = (host || '');
    try {
      if (ipPart && window._nodedb_cache && window._nodedb_cache[ipPart] && window._nodedb_cache[ipPart].n) {
        var realNode = window._nodedb_cache[ipPart].n;
        if (realNode && typeof displayHost === 'string') {
          displayHost = displayHost.replace(/\bnodename\b/g, realNode);
        }
      }
    } catch(e) { /* ignore lookup errors */ }

    // Update or create hostname span without touching other children (preserve debug button etc.)
    var hostnameSpan = el.querySelector('#hostname');
    if (!hostnameSpan) {
      hostnameSpan = document.createElement('span');
      hostnameSpan.id = 'hostname';
      // append at the end by default
      el.appendChild(hostnameSpan);
    }
    try { hostnameSpan.textContent = displayHost || ''; } catch(e) { hostnameSpan.innerText = displayHost || ''; }
    // ensure an icon wrapper exists if needed
    if (iconHtml) {
      var iconWrap = el.querySelector('.fetch-icon');
      if (!iconWrap) {
        iconWrap = document.createElement('span');
        iconWrap.className = 'fetch-icon';
        // insert before hostnameSpan if possible
        el.insertBefore(iconWrap, hostnameSpan);
      }
      // replace raw HTML insertion with safe DOM parse via a template
      try {
        iconWrap.innerHTML = '';
        var tmp = document.createElement('div'); tmp.innerHTML = iconHtml || '';
        while (tmp.firstChild) iconWrap.appendChild(tmp.firstChild);
      } catch(e) { iconWrap.textContent = iconHtml || ''; }
    } else {
      var iconWrapRem = el.querySelector('.fetch-icon'); if (iconWrapRem) iconWrapRem.parentNode.removeChild(iconWrapRem);
    }
    // Also update compact header host element if present
  // Do not overwrite the brand 'main-host' which is reserved for compact IP display.
  // Update page-level host element instead.
  try { var pageHostEl = document.getElementById('main-host-page'); if (pageHostEl) { pageHostEl.textContent = displayHost || ''; } } catch(e) {}
  // Also update the page-level host element where present
  try { var pageHost = document.getElementById('main-host-page'); if (pageHost) { pageHost.textContent = displayHost || ''; } } catch(e) {}
  } catch (e) {
    // fallback simple text
    el.textContent = (ip ? ip + ' - ' : '') + (host || '');
  }
  // make nav-host clickable to open fetch-debug modal (non-destructive)
  try {
    el.style.cursor = 'pointer';
    // attach click handler only once
    if (!el._fetchDebugHandlerAttached) {
      el.addEventListener('click', function(){
        var body = document.getElementById('fetch-debug-body');
        if (!body) return;
        body.textContent = 'Loading...';
        fetch('/fetch_debug', {cache:'no-store'}).then(function(r){ return r.text(); }).then(function(t){ try { var obj = JSON.parse(t); body.textContent = JSON.stringify(obj, null, 2); } catch(e) { body.textContent = t; } }).catch(function(e){ body.textContent = 'ERR: '+e; });
        showModal('fetch-debug-modal');
      });
      el._fetchDebugHandlerAttached = true;
    }
  } catch(e) {}
}

function setLoginLink(url, port) {
  var nav = document.getElementById('nav-login');
  var link = document.getElementById('nav-login-link');
  if (!nav || !link) return;
  if (!url) { nav.style.display = 'none'; return; }
  // if port provided, include it
  link.href = url;
  nav.style.display = '';
}

function renderConnectionsTable(c, nodedb) {
  var tbody = document.querySelector('#connectionsTable tbody');
  tbody.innerHTML = '';
  if (!c || !c.ports) return;
  // Build simple IP->hostname map if nodedb given as array
  // Build IP -> { hostname, node, any } mapping to allow separating hostname vs node name
  var ipToHost = {};
  if (nodedb) {
    if (Array.isArray(nodedb)) {
      nodedb.forEach(function(entry){
        if (!entry) return;
        var ip = entry.ipv4 || entry.ip || '';
        if (!ip) return;
  // nodedb array entries may provide device/name/id fields.
  // Prefer device (d) or hostname field for the Hostname column,
  // and the node/group name (n or name) for the Node column.
  var hostname = entry.d || entry.hostname || entry.h || '';
  var node = entry.name || entry.n || '';
  var any = hostname || node || entry.m || '';
        ipToHost[ip] = { hostname: hostname, node: node, any: any };
      });
    } else if (typeof nodedb === 'object') {
      Object.keys(nodedb).forEach(function(k){
        var v = nodedb[k]; if (!v) return;
        // The live nodedb uses keys like 'n' (node name), 'd' (device/hostname),
        // 'h' (host hint) and 'm' (master). Prefer device/host fields for Hostname.
        var hostname = v.d || v.hostname || v.h || '';
        var node = v.name || v.n || '';
        var any = hostname || node || v.m || '';
        ipToHost[k] = { hostname: hostname, node: node, any: any };
      });
    }
  }
  c.ports.forEach(function(p){
    var tr = document.createElement('tr');
  // use global td(val, allowHtml) helper
    tr.appendChild(td(p.port));
    tr.appendChild(td(p.bridge || ''));
    tr.appendChild(td((p.macs || []).join('<br>')));
    tr.appendChild(td((p.ips || []).join('<br>')));
    /* Resolve Hostname and Node separately from nodedb mapping (prefer explicit hostname field) */
    var hostnameVal = '';
    var nodeNames = [];
    if (p.ips && p.ips.length > 0) {
      p.ips.forEach(function(ip){
        var m = ipToHost[ip];
        if (!m) return;
        // prefer an explicit hostname for the Hostname column
        if (!hostnameVal && m.hostname) hostnameVal = m.hostname;
        // collect node names (if present)
        if (m.node) nodeNames.push(m.node);
        // if no explicit node name but we have a hostname and no hostnameVal yet, fallback will have used it
      });
      // if we still have no hostnameVal but some mapping exists, fallback to first available 'any' value
      if (!hostnameVal) {
        for (var ii=0; ii<p.ips.length; ii++) { var mm = ipToHost[p.ips[ii]]; if (mm && mm.any) { hostnameVal = mm.any; break; } }
      }
    }
    // dedupe nodeNames
    if (nodeNames.length) {
      var uniq = [];
      nodeNames.forEach(function(nm){ if (uniq.indexOf(nm) === -1) uniq.push(nm); });
      nodeNames = uniq;
    }
    // Build full hostname: resolved hostname + ".<node>.wien.funkfeuer.at" when node present
    var fullHostname = (hostnameVal || '').toString();
    var primaryNode = (nodeNames && nodeNames.length) ? nodeNames[0] : '';
    // sanitize trailing dot
    if (fullHostname && fullHostname.slice(-1) === '.') fullHostname = fullHostname.slice(0, -1);
    if (primaryNode) {
      if (fullHostname) fullHostname = fullHostname + '.' + primaryNode + '.wien.funkfeuer.at';
      else fullHostname = primaryNode + '.wien.funkfeuer.at';
    }
    // Build host cell: prefer clickable anchor when we have a fullHostname
    var hostTd = document.createElement('td');
    if (fullHostname) {
      var safeHost = String(fullHostname).replace(/</g,'&lt;').replace(/>/g,'&gt;');
      var a = document.createElement('a'); a.target = '_blank'; a.href = 'https://' + safeHost; a.textContent = safeHost; hostTd.appendChild(a);
    } else if (hostnameVal) {
      hostTd.textContent = String(hostnameVal).replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }
    tr.appendChild(hostTd);
    var nodesTd = document.createElement('td');
    if (nodeNames && nodeNames.length) {
      nodeNames.forEach(function(n){ var d = document.createElement('div'); d.textContent = n; nodesTd.appendChild(d); });
    }
    tr.appendChild(nodesTd);
    tbody.appendChild(tr);
  });
  var headers = document.querySelectorAll('#connectionsTable th');
  headers.forEach(function(h){ h.style.cursor='pointer'; h.onclick = function(){ sortTableByColumn(h.getAttribute('data-key')); }; });
  // Ensure the connections tab pane is visible after rendering (fix intermittent hidden-tab issue)
  try { var pane = document.getElementById('tab-connections'); if (pane) { pane.classList.remove('hidden'); pane.style.display = ''; } } catch(e){}
}

function renderVersionsPanel(v) {
  var wrap = document.getElementById('versions-wrap'); if(!wrap) return; while(wrap.firstChild) wrap.removeChild(wrap.firstChild);
  if(!v) {
    var alert = document.createElement('div'); alert.className = 'alert alert-warning';
    var icon = document.createElement('i'); icon.className = 'glyphicon glyphicon-exclamation-sign'; alert.appendChild(icon);
    alert.appendChild(document.createTextNode(' No versions data available'));
    wrap.appendChild(alert);
    return;
  }

  // Main container with improved styling
  var container = document.createElement('div');
  container.className = 'versions-container';

  // Compact Header section (single-line) with system overview and right-aligned badges
  var headerCard = document.createElement('div');
  // use panel-default for a smaller visual footprint
  headerCard.className = 'panel panel-default';
  var headerBody = document.createElement('div');
  headerBody.className = 'panel-body';
  // make it a compact single-line flex row
  headerBody.style.display = 'flex';
  headerBody.style.alignItems = 'center';
  headerBody.style.justifyContent = 'space-between';
  headerBody.style.padding = '6px 10px';

  // Left side - minimal System info
  var leftCol = document.createElement('div');
  leftCol.className = 'header-left';
  leftCol.style.display = 'flex';
  leftCol.style.flexDirection = 'column';
  leftCol.style.fontSize = '13px';
  leftCol.style.fontWeight = '600';
  var systemInfo = document.createElement('div');
  var smallInfo = (v.system ? v.system + '  ' : '') + (v.ipv4 || 'No IP');
  var titleDiv = document.createElement('div'); titleDiv.style.fontWeight = '700'; titleDiv.textContent = (v.hostname || 'System');
  var smallDiv = document.createElement('div'); smallDiv.style.fontSize = '11px'; smallDiv.style.color = '#666'; smallDiv.style.marginTop = '2px'; smallDiv.textContent = smallInfo;
  systemInfo.appendChild(titleDiv); systemInfo.appendChild(smallDiv);
  leftCol.appendChild(systemInfo);

  // Right side - Status badges
  var rightCol = document.createElement('div');
  rightCol.className = 'header-right';
  rightCol.style.display = 'flex';
  rightCol.style.alignItems = 'center';
  rightCol.style.gap = '10px';
  var badgeContainer = document.createElement('div');
  badgeContainer.className = 'status-badges';
  // Row wrapper for left and right columns
  var headerRow = document.createElement('div');
  headerRow.style.display = 'flex';
  headerRow.style.alignItems = 'center';
  headerRow.style.justifyContent = 'space-between';
  headerRow.style.width = '100%';

  // Compact status badge helper per user rules: show green OK (with check) when binary exists and running,
  // red X when binary exists but not running, grey X when binary not present.
  function createOlsrStatusBadge(binaryName, exists, running) {
    var badge = document.createElement('span');
    badge.className = 'status-olsr-badge';
    badge.style.display = 'inline-flex';
    badge.style.alignItems = 'center';
    badge.style.gap = '6px';
    badge.style.padding = '4px 8px';
    badge.style.borderRadius = '12px';
    badge.style.fontSize = '12px';
    badge.style.fontWeight = '600';
    var icon = document.createElement('span');
    icon.style.display = 'inline-block';
    icon.style.width = '14px';
    icon.style.height = '14px';
    icon.style.borderRadius = '50%';
    icon.style.textAlign = 'center';
    icon.style.lineHeight = '14px';
    icon.style.color = '#fff';
    icon.style.fontSize = '11px';
    var label = document.createElement('span');
    label.textContent = binaryName;

    if (!exists) {
      // grey X
      icon.style.background = '#6c757d';
      icon.textContent = '✖';
      badge.style.background = '#ececec';
      badge.style.color = '#333';
    } else if (exists && running) {
      // green OK
      icon.style.background = '#2ecc71';
      icon.textContent = '✓';
      badge.style.background = '#e6f9ee';
      badge.style.color = '#145a2b';
    } else {
      // exists but not running -> red X
      icon.style.background = '#e74c3c';
      icon.textContent = '✖';
      badge.style.background = '#fff0f0';
      badge.style.color = '#7a1d1d';
    }
    badge.appendChild(icon);
    badge.appendChild(label);
    return badge;
  }

  // Append OLSRd / OLSRd2 compact badges based on versions payload (versions.json renders into `v`)
  try {
    if (typeof v.olsrd_exists !== 'undefined') {
      badgeContainer.appendChild(createOlsrStatusBadge('olsrd', v.olsrd_exists, v.olsrd_running));
    }
    if (typeof v.olsr2_exists !== 'undefined') {
      badgeContainer.appendChild(createOlsrStatusBadge('olsrd2', v.olsr2_exists, v.olsr2_running));
    }
  } catch (e) { /* ignore UI errors */ }

  // append badges to the right column (no refresh button per user request)
  rightCol.appendChild(badgeContainer);
  headerRow.appendChild(leftCol);
  headerRow.appendChild(rightCol);
  headerBody.appendChild(headerRow);
  headerCard.appendChild(headerBody);
  // Move header into the global header placeholder so it's visible across tabs.
  var globalHeader = document.getElementById('global-versions-header');
  try {
    if (globalHeader) {
      // Clear any previous content and append the header card
  while(globalHeader.firstChild) globalHeader.removeChild(globalHeader.firstChild);
      globalHeader.appendChild(headerCard);
    } else {
      // Fallback: keep header in the versions container if placeholder is missing
      container.appendChild(headerCard);
    }
  } catch (e) {
    // If DOM manipulation fails for any reason, fallback to container append
    try { container.appendChild(headerCard); } catch (ee) { /* ignore */ }
  }

  // Information cards in a grid
  var infoGrid = document.createElement('div');
  infoGrid.className = 'row';
  infoGrid.style.marginTop = '20px';

  // System Information Card
  var systemCard = createInfoCard('System Information', 'hdd', [
    { label: 'System Type', value: v.system || 'Unknown', icon: 'tag' },
    { label: 'Hostname', value: v.hostname || 'Unknown', icon: 'user' },
    { label: 'IPv4 Address', value: v.ipv4 || 'Not available', icon: 'globe' },
    { label: 'IPv6 Address', value: v.ipv6 || 'Not available', icon: 'globe' },
    { label: 'Link Serial', value: v.linkserial || 'Not available', icon: 'link' }
  ]);
  infoGrid.appendChild(systemCard);

  // OLSR Information Card
  var olsrCard = createInfoCard('OLSR Routing', 'transfer', [
    { label: 'OLSRd Status', value: v.olsrd_running ? '<span class="text-success">Running</span>' : '<span class="text-danger">Stopped</span>', icon: 'play-circle' },
    { label: 'OLSRv2 Status', value: v.olsr2_running ? '<span class="text-success">Running</span>' : '<span class="text-danger">Stopped</span>', icon: 'play-circle' },
    { label: 'OLSRd Version', value: v.olsrd_details ? v.olsrd_details.version : (v.olsrd || 'Unknown'), icon: 'info-sign' },
    { label: 'Watchdog', value: v.olsrd4watchdog ? '<span class="text-success">Active</span>' : '<span class="text-muted">Inactive</span>', icon: 'eye-open' }
  ]);
  infoGrid.appendChild(olsrCard);

  // Software Information Card
  var softwareItems = [
    { label: 'BMK Webstatus', value: v.bmk_webstatus || 'Not available', icon: 'cloud' },
    { label: 'AutoUpdate Wizards', value: v.autoupdate_wizards_installed || 'Not installed', icon: 'refresh' }
  ];

  if (v.olsrd_details && v.olsrd_details.description) {
    softwareItems.push({ label: 'OLSRd Description', value: v.olsrd_details.description, icon: 'file' });
  }

  if (v.bootimage && v.bootimage.md5 && v.bootimage.md5 !== 'n/a') {
    softwareItems.push({ label: 'Boot Image MD5', value: v.bootimage.md5, icon: 'lock' });
  }

  var softwareCard = createInfoCard('Software & Updates', 'cog', softwareItems);
  infoGrid.appendChild(softwareCard);

  // AutoUpdate Settings Card (if available)
  if (v.autoupdate_settings) {
    var autoupdateItems = [];
    Object.keys(v.autoupdate_settings).forEach(function(key) {
      var value = v.autoupdate_settings[key];
      var displayValue = typeof value === 'boolean' ? (value ? 'Enabled' : 'Disabled') : String(value);
      autoupdateItems.push({
        label: key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        value: displayValue,
        icon: value ? 'ok' : 'remove'
      });
    });
    var autoupdateCard = createInfoCard('AutoUpdate Configuration', 'wrench', autoupdateItems);
    infoGrid.appendChild(autoupdateCard);
  }

  container.appendChild(infoGrid);

  // Collapsible raw data section
  var rawDataSection = document.createElement('div');
  rawDataSection.className = 'panel panel-default';
  rawDataSection.style.marginTop = '20px';

  var rawDataHeader = document.createElement('div');
  rawDataHeader.className = 'panel-heading';
  rawDataHeader.innerHTML = '';
  var h4 = document.createElement('h4'); h4.className = 'panel-title'; var a = document.createElement('a'); a.setAttribute('data-toggle','collapse'); a.setAttribute('href','#rawVersionsData'); var i = document.createElement('i'); i.className='glyphicon glyphicon-chevron-down'; a.appendChild(i); a.appendChild(document.createTextNode(' Raw Version Data')); h4.appendChild(a); rawDataHeader.appendChild(h4);
  rawDataSection.appendChild(rawDataHeader);

  var rawDataBody = document.createElement('div');
  rawDataBody.id = 'rawVersionsData';
  rawDataBody.className = 'panel-collapse collapse';
  var rawDataContent = document.createElement('div');
  rawDataContent.className = 'panel-body';
  var pre = document.createElement('pre');
  pre.style.maxHeight = '300px';
  pre.style.overflow = 'auto';
  pre.className = 'json-data';
  pre.textContent = JSON.stringify(v, null, 2);
  rawDataContent.appendChild(pre);
  rawDataBody.appendChild(rawDataContent);
  rawDataSection.appendChild(rawDataBody);

  container.appendChild(rawDataSection);

  // Add custom CSS for better styling
  if (!document.getElementById('versions-custom-css')) {
    var style = document.createElement('style');
    style.id = 'versions-custom-css';
    style.textContent = `
      .versions-container .panel { margin-bottom: 15px; }
      .versions-container .info-item { margin-bottom: 8px; padding: 8px; border-radius: 4px; background: #f8f9fa; }
      .versions-container .info-item:hover { background: #e9ecef; }
      .versions-container .info-label { font-weight: 600; color: #495057; }
      .versions-container .info-value { color: #6c757d; word-break: break-all; }
      .versions-container .status-badge { font-size: 12px; margin-right: 8px; margin-bottom: 4px; }
      .versions-container .json-data { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 10px; }
      .versions-container .panel-primary .panel-heading { background: linear-gradient(135deg, #007bff, #0056b3); }
    `;
    document.head.appendChild(style);
  }

  wrap.appendChild(container);

  // Helper function to create info cards
  function createInfoCard(title, icon, items) {
    var col = document.createElement('div');
    col.className = 'col-md-6';

    var card = document.createElement('div');
    card.className = 'panel panel-info';

  var cardHeader = document.createElement('div');
  cardHeader.className = 'panel-heading';
  var h5 = document.createElement('h5');
  var ih = document.createElement('i'); ih.className = 'glyphicon glyphicon-' + icon; h5.appendChild(ih); h5.appendChild(document.createTextNode(' ' + title));
  cardHeader.appendChild(h5);
  card.appendChild(cardHeader);

    var cardBody = document.createElement('div');
    cardBody.className = 'panel-body';

    items.forEach(function(item) {
  var itemDiv = document.createElement('div');
  itemDiv.className = 'info-item';
  var labelDiv = document.createElement('div'); labelDiv.className = 'info-label';
  var li = document.createElement('i'); li.className = 'glyphicon glyphicon-' + item.icon; labelDiv.appendChild(li); labelDiv.appendChild(document.createTextNode(' ' + item.label));
  var valDiv = document.createElement('div'); valDiv.className = 'info-value'; valDiv.textContent = item.value;
  itemDiv.appendChild(labelDiv); itemDiv.appendChild(valDiv);
  cardBody.appendChild(itemDiv);
    });

    card.appendChild(cardBody);
    col.appendChild(card);
    return col;
  }
}

function sortTableByColumn(key) {
  var tbody = document.querySelector('#connectionsTable tbody');
  if(!tbody) return;
  var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
  rows.sort(function(a,b){
    var idx = getColumnIndexByKey(key);
    var va = a.cells[idx] ? a.cells[idx].textContent.trim() : '';
    var vb = b.cells[idx] ? b.cells[idx].textContent.trim() : '';
    // Fallback for older browsers that don't support localeCompare options
    if (typeof va.localeCompare === 'function' && va.localeCompare.length >= 2) {
      return va.localeCompare(vb, undefined, {numeric:true});
    } else {
      return va.localeCompare(vb);
    }
  });
  rows.forEach(function(r){ tbody.appendChild(r); });
}

function getColumnIndexByKey(key){
  var ths = document.querySelectorAll('#connectionsTable th');
  for(var i=0;i<ths.length;i++){ if(ths[i].getAttribute('data-key')===key) return i; }
  return 0;
}

function populateTracerouteTable(tracerouteData) {
  var tbody = document.querySelector('#tracerouteTable tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  try { if (window._uiDebug) console.debug('populateTracerouteTable called, rows=', (tracerouteData && tracerouteData.length) || 0); } catch(e){}
  if (!tracerouteData || !Array.isArray(tracerouteData)) return;
  tracerouteData.forEach(function(hop) {
    var tr = document.createElement('tr');
  // use global td(val, allowHtml) helper
    var ip = hop.ip || '';
    var hostname = hop.hostname || hop.host || '';
    // if hostname empty but ip looks like a hostname? leave blank; if ip not numeric maybe treat as hostname
    if (!hostname && ip && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ip) && ip.indexOf(':')<0) { hostname = ip; }
    tr.appendChild(td(hop.hop || ''));
    tr.appendChild(td(ip ? ('<a href="https://' + ip + '" target="_blank">' + ip + '</a>') : ''));
    var hostnameCell = td(hostname ? ('<a href="https://' + hostname + '" target="_blank">' + hostname + '</a>') : '');
    // attempt lightweight reverse lookup via existing connections/nodedb if available globally
    if (!hostname && ip && window._nodedb_cache) {
      try {
        var hnObj = window._nodedb_cache[ip];
        if (hnObj) {
          // prefer the human name field (.n), then hostname/h, then fallback to string
          var resolvedName = (typeof hnObj === 'string') ? hnObj : (hnObj.n || hnObj.hostname || hnObj.h || null);
          if (resolvedName) {
            hostnameCell.textContent = '';
            var a = document.createElement('a'); a.href = 'https://' + resolvedName; a.target = '_blank'; a.textContent = resolvedName; hostnameCell.appendChild(a);
          }
        }
      } catch(e){}
    }
    tr.appendChild(hostnameCell);
    var pingVal = hop.ping || '';
    if (pingVal) {
      // Preserve original formatting if it already includes ms (avoid adding extra space)
      var pv = String(pingVal).trim();
      if (/ms$/i.test(pv)) {
        // normalize to lowercase ms
        pv = pv.replace(/MS$/,'ms');
        tr.appendChild(td(pv));
      } else if (pv === '*') {
        tr.appendChild(td('*'));
      } else {
        // just a number, append ms without extra space to match python reference style
        tr.appendChild(td(pv + 'ms'));
      }
    } else tr.appendChild(td(''));
    tbody.appendChild(tr);
  });
  // Ensure traceroute tab pane is visible after rendering
  try { var pane = document.getElementById('tab-traceroute'); if (pane) { pane.classList.remove('hidden'); pane.style.display = ''; } } catch(e){}
  try { window._traceroutePopulatedAt = Date.now(); } catch(e){}
  // If nodedb wasn't available at render time, attempt a short re-enrichment
  try {
    if ((!window._nodedb_cache || Object.keys(window._nodedb_cache).length === 0) && typeof window._traceroute_enrich_retry === 'undefined') {
      window._traceroute_enrich_retry = 0;
      var enrichInterval = setInterval(function(){
        try {
          if (window._nodedb_cache && Object.keys(window._nodedb_cache).length > 0) {
            // re-run lightweight enrichment on table rows
            var tbody = document.querySelector('#tracerouteTable tbody');
            if (!tbody) { clearInterval(enrichInterval); return; }
            var rows = tbody.querySelectorAll('tr');
            for (var ri = 0; ri < rows.length; ri++) {
              try {
                var cells = rows[ri].children;
                if (!cells || cells.length < 3) continue;
                var ipLink = cells[1].querySelector('a');
                var hostCell = cells[2];
                if (ipLink && ipLink.textContent && (!hostCell || !hostCell.textContent || hostCell.textContent.trim() === '')) {
                  var ip = ipLink.textContent.trim();
                  var obj = window._nodedb_cache[ip];
                  if (obj) {
                    var name = (typeof obj === 'string') ? obj : (obj.n || obj.hostname || obj.h || null);
                    if (name) {
                      hostCell.textContent = '';
                      var a2 = document.createElement('a'); a2.href = 'https://' + name; a2.target = '_blank'; a2.textContent = name; hostCell.appendChild(a2);
                    }
                  }
                }
              } catch(e) {}
            }
            clearInterval(enrichInterval);
          }
          window._traceroute_enrich_retry++;
          if (window._traceroute_enrich_retry > 6) { clearInterval(enrichInterval); }
        } catch(e) { clearInterval(enrichInterval); }
      }, 1000);
    }
  } catch(e) {}
}
          // expose nodedb for traceroute hostname enrichment
          try { window._nodedb_cache = nodedb; } catch(e){}

function runTraceroute(){
  try { if (window._uiDebug) console.debug('runTraceroute invoked'); } catch(e){}
  var targetEl = document.getElementById('tr-host');
  if (!targetEl) { console.error('Traceroute input element #tr-host not found'); return; }
  var target = (targetEl.value || '').trim();
  if(!target) return alert('Enter target for traceroute');
  var pre = document.getElementById('p-traceroute');
  // add a small visible summary near the hostname so users get immediate feedback
  var summaryEl = document.getElementById('traceroute-summary');
  if (!summaryEl) {
    var hostEl = document.getElementById('hostname');
    if (hostEl && hostEl.parentNode) {
      summaryEl = document.createElement('div');
      summaryEl.id = 'traceroute-summary';
      summaryEl.style.margin = '6px 0';
      summaryEl.style.fontSize = '90%';
      hostEl.parentNode.insertBefore(summaryEl, hostEl.nextSibling);
    }
  }
  if (summaryEl) summaryEl.textContent = 'Traceroute: running ...';
  if (pre) pre.style.display='block';
  if (pre) pre.textContent='Running traceroute...';
  fetch('/traceroute?target='+encodeURIComponent(target),{cache:'no-store'}).then(function(r){ return r.text(); }).then(function(t){
  if (pre) pre.textContent = t;
  try { if (window._uiDebug) console.debug('traceroute raw output length=', t.length); } catch(e){}
    // Try to parse and populate table (supports numeric -n output and hostname (ip) formats)
    try {
      var lines = t.split('\n');
      var hops = [];
      var lineRegex = /^\s*(\d+)\s+(.*)$/;
      for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (!line) continue;
        var m = line.match(lineRegex);
        if (!m) continue;
        var hopnum = m[1];
        var rest = m[2];
        var ip = '';
        var hostname = '';
        var ping = '';
        // capture ip in parentheses: hostname (ip) ...
        var paren = rest.match(/\(([^)]+)\)/);
        if (paren) {
          ip = paren[1];
          hostname = rest.replace(/\([^)]*\)/, '').trim().split(/\s+/)[0] || '';
        } else {
          var tokens = rest.split(/\s+/);
          if (tokens.length > 0) {
            var tok0 = tokens[0];
            var isIpv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(tok0);
            var isIpv6 = tok0.indexOf(':') >= 0;
            if (isIpv4 || isIpv6) { ip = tok0; }
            else { hostname = tok0; if (tokens.length > 1) { var maybeIp = tokens[1].replace(/^[()]+|[()]+$/g, ''); if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(maybeIp) || maybeIp.indexOf(':') >= 0) ip = maybeIp; } }
          }
        }
        var pingMatch = rest.match(/(\d+(?:\.\d+)?)\s*ms/);
        if (pingMatch) ping = pingMatch[1]; else { var numMatch = rest.match(/(\d+(?:\.\d+)?)(?!.*\d)/); if (numMatch) ping = numMatch[1]; }
        hops.push({ hop: hopnum, ip: ip, hostname: hostname, ping: ping });
      }
      if (hops.length > 0) {
        populateTracerouteTable(hops);
        if (pre) { pre.style.display='none'; }
        if (summaryEl) summaryEl.textContent = 'Traceroute: ' + hops.length + ' hop(s)';
  try { if (window._uiDebug) console.debug('Traceroute parsed', hops.length, 'hops'); } catch(e){}
      } else {
        // fallback: try simpler token parsing per-line
        try {
          var fhops = [];
          for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim(); if (!line) continue;
            var tokens = line.split(/\s+/);
            if (tokens.length === 0) continue;
            if (!/^\d+$/.test(tokens[0])) continue;
            var hnum = tokens[0];
            var hip = '';
            var hname = '';
            var hping = '';
            if (tokens.length === 2) { hip = tokens[1]; }
            else if (tokens.length >= 3) {
              // tokens like: hop host (ip) t ms  OR hop ip t ms OR hop host ip t ms
              // find token that looks like IP
              for (var j = 1; j < tokens.length; j++) {
                var tok = tokens[j].replace(/^[()]+|[()]+$/g, '');
                if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(tok) || tok.indexOf(':')>=0) { hip = tok; }
              }
              // hostname is first token after hop that is not the ip
              for (var j = 1; j < tokens.length; j++) {
                var tok = tokens[j].replace(/^[()]+|[()]+$/g, '');
                if (tok && tok !== hip) { hname = tok; break; }
              }
              // ping: look for ms
              var pMatch = line.match(/(\d+(?:\.\d+)?)\s*ms/);
              if (pMatch) hping = pMatch[1];
            }
            fhops.push({ hop: hnum, ip: hip, hostname: hname, ping: hping });
          }
          if (fhops.length > 0) { populateTracerouteTable(fhops); if (pre) pre.style.display='none'; if (summaryEl) summaryEl.textContent = 'Traceroute: ' + fhops.length + ' hop(s)'; }
        } catch(e) { /* ignore */ }
        if (summaryEl && (!fhops || fhops.length === 0)) {
          var one = t.split('\n')[0] || t;
          summaryEl.textContent = 'Traceroute: no hops parsed. First line: ' + (one.length>200?one.substr(0,200)+'...':one);
        }
      }
    } catch (e) { /* ignore parsing errors */ }
  }).catch(function(e){ if (pre) pre.textContent = 'ERR: '+e; });
}

// Legacy OLSRd presence detection
  function detectLegacyOlsrd(cb){
    // Be tolerant: /status may sometimes include non-JSON wrapper text on some systems.
    // Fetch as text and try to extract the first JSON object instead of relying on r.json().
    // Use the tolerant safeFetchStatus to parse /status (handles concatenated
    // JSON and wrapper text). This avoids hard JSON.parse failures on some
    // embedded systems that emit multiple objects.
    safeFetchStatus({cache:'no-store'}).then(function(st){
      // st may be null if parsing failed inside safeFetchStatus
      // Determine whether to show legacy OLSR tab. If status doesn't explicitly
      // indicate legacy olsrd, probe the /olsr/links endpoint before hiding the tab
      // so we don't incorrectly hide it when live data exists elsewhere.
      var show = false;
      try {
        if (st) {
          /*
           * Show the legacy OLSR tab when the backend indicates olsrd is present
           * or when a links array is provided. Previously this check suppressed
           * the legacy tab when olsr2 was running which hid useful legacy
           * data on systems that run both daemons.
           */
          if (st.olsrd_on || (st.links && Array.isArray(st.links) && st.links.length)) show = true;
        }
      } catch(e) { show = false; }

      var linkTab = document.querySelector('#mainTabs a[href="#tab-olsr"]');
      if (!show && linkTab) {
        // status didn't indicate OLSRd; probe /olsr/links to be sure
        try {
          fetch('/olsr/links', {cache:'no-store'}).then(function(r){ return r.json(); }).then(function(res){
            try {
              if (res && Array.isArray(res.links) && res.links.length) {
                show = true;
              }
            } catch(e) {}
            if (window._uiDebug) console.debug('detectLegacyOlsrd: setting OLSR tab visibility to', show, 'after probing /olsr/links');
            linkTab.parentElement.style.display = show ? '' : 'none';
            if (cb) cb(show);
          }).catch(function(){
            // probe failed — do not aggressively hide; keep current behavior conservative
            if (window._uiDebug) console.debug('detectLegacyOlsrd: /olsr/links probe failed; leaving OLSR tab hidden');
            linkTab.parentElement.style.display = 'none';
            if (cb) cb(false);
          });
          return; // early return since probe will call cb
        } catch(e) { /* fallthrough to default hide */ }
      }
      if (linkTab) {
        if (window._uiDebug) console.debug('detectLegacyOlsrd: setting OLSR tab visibility to', show);
        linkTab.parentElement.style.display = show? '' : 'none';
      }
      if (cb) cb(show);
  }).catch(function(err){ var linkTab = document.querySelector('#mainTabs a[href="#tab-olsr"]'); if (linkTab) { if (window._uiDebug) console.debug('detectLegacyOlsrd: fetch failed, leaving OLSR tab visibility unchanged:', err); } if(cb) cb(false); });
  }
  detectLegacyOlsrd();

// --- Per-table search & generic sorting wiring (applies to main tables, avoids modal tables) ---
;(function(){
  function normalizeText(s){ return (s||'').toString().toLowerCase(); }

  function filterTableByQuery(table, q){
    if (!table) return;
    q = normalizeText(q || '');
    var tbody = table.tBodies[0]; if(!tbody) return;
    var rows = Array.prototype.slice.call(tbody.rows || []);
    rows.forEach(function(r){ var txt = normalizeText(r.textContent || ''); r.style.display = (q === '' || txt.indexOf(q) !== -1) ? '' : 'none'; });
  }

  function sortTable(table, colIndex){
    if (!table) return;
    var tbody = table.tBodies[0]; if(!tbody) return;
    var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
    var asc = true;
    var prevIdx = table.getAttribute('data-sort-col');
    if (prevIdx !== null && prevIdx !== undefined && String(prevIdx) === String(colIndex)) {
      asc = table.getAttribute('data-sort-asc') !== 'true';
    }
    // store new state
    table.setAttribute('data-sort-col', String(colIndex));
    table.setAttribute('data-sort-asc', asc ? 'true' : 'false');

    rows.sort(function(a,b){
      var aCell = a.cells[colIndex] ? (a.cells[colIndex].textContent || '') : '';
      var bCell = b.cells[colIndex] ? (b.cells[colIndex].textContent || '') : '';
      var an = parseFloat(aCell.replace(/[^0-9\.\-]/g,''));
      var bn = parseFloat(bCell.replace(/[^0-9\.\-]/g,''));
      if (!isNaN(an) && !isNaN(bn)) {
        return asc ? (an - bn) : (bn - an);
      }
      var av = normalizeText(aCell);
      var bv = normalizeText(bCell);
      if (av < bv) return asc ? -1 : 1;
      if (av > bv) return asc ? 1 : -1;
      return 0;
    });
    rows.forEach(function(r){ tbody.appendChild(r); });
    // update header indicators
    try {
      var ths = table.tHead.querySelectorAll('th');
      ths.forEach(function(th, i){
        var mark = th.querySelector('.sort-mark'); if (!mark) { mark = document.createElement('span'); mark.className='sort-mark'; mark.style.marginLeft='6px'; mark.textContent='↕'; th.appendChild(mark); }
        if (i === colIndex) { mark.textContent = table.getAttribute('data-sort-asc') === 'true' ? '▲' : '▼'; }
        else { mark.textContent = '↕'; }
      });
    } catch(e) {}
  }

  // wire search inputs
  try {
    var inputs = document.querySelectorAll('.table-search-input');
    inputs.forEach(function(inp){
      var tgt = inp.getAttribute('data-target');
      if (!tgt) return;
      var table = document.querySelector(tgt);
      inp.addEventListener('input', function(){ filterTableByQuery(table, inp.value); });
    });
  } catch(e) {}

  // wire generic header sorting for non-modal tables
  try {
    var allTables = document.querySelectorAll('table');
    allTables.forEach(function(table){
      if (!table.id) return;
      // skip modal/internal tables that already have dedicated sorting
      if (table.id === 'route-modal-table' || table.id === 'node-modal-table') return;
      var thead = table.tHead; if(!thead) return;
      var ths = thead.querySelectorAll('th');
      ths.forEach(function(th, idx){
        // attach pointer cursor
        th.style.cursor = 'pointer';
  // ensure a small sort mark element exists (default hint '↕')
  if (!th.querySelector('.sort-mark')) { var sm = document.createElement('span'); sm.className='sort-mark'; sm.style.marginLeft='6px'; sm.textContent='↕'; th.appendChild(sm); }
        th.addEventListener('click', function(){ sortTable(table, idx); });
      });
    });
  } catch(e) {}
})();

// Wire fetch debug modal close on DOM load so it's always available
document.addEventListener('DOMContentLoaded', function(){
  var closeBtn = document.getElementById('fetch-debug-close');
  if (closeBtn) closeBtn.addEventListener('click', function(){ hideModal('fetch-debug-modal'); });
  var rClose = document.getElementById('route-modal-close'); if (rClose) rClose.addEventListener('click', function(){ hideModal('route-modal'); });
  var nClose = document.getElementById('node-modal-close'); if (nClose) nClose.addEventListener('click', function(){ hideModal('node-modal'); });
  // overlay clicks: close any modal when clicking the overlay outside the panel
  var overlays = document.querySelectorAll('.modal-overlay');
  overlays.forEach(function(o){ o.addEventListener('click', function(e){ if (e.target === o) { try { o.setAttribute('aria-hidden','true'); o.style.display='none'; } catch(e){} } }); });
});

// Runtime debug overlay (non-invasive): shows computed display and table row counts for key tabs
(function(){
  function createDebugOverlay(){
    if (document.getElementById('ui-debug-overlay')) return;
    var o = document.createElement('div');
    o.id = 'ui-debug-overlay';
    o.style.position = 'fixed'; o.style.right = '12px'; o.style.top = '12px'; o.style.zIndex = '9999';
    o.style.background = 'rgba(0,0,0,0.7)'; o.style.color = '#fff'; o.style.padding = '8px 10px';
    o.style.fontSize = '12px'; o.style.lineHeight = '1.2'; o.style.borderRadius = '6px'; o.style.maxWidth = '360px';
    o.style.fontFamily = 'monospace'; o.style.whiteSpace = 'pre-wrap'; o.style.pointerEvents = 'none';
    document.body.appendChild(o);
    function update(){
      try {
  var ids = ['#tab-status','#tab-olsr','#tab-stats','#tab-connections','#tab-traceroute','#tab-log'];
        var out = [];
        ids.forEach(function(id){
          var el = document.querySelector(id);
          if (!el) { out.push(id + ': MISSING'); return; }
          var cs = window.getComputedStyle(el);
          var tables = el.querySelectorAll('table');
          var rows = [];
          tables.forEach(function(t){ try { var r = t.querySelectorAll('tbody tr').length; rows.push((t.id||t.className||t.tagName)+':'+r); } catch(e){} });
          out.push(id + ' display=' + cs.display + ' visible=' + (cs.display!=='none') + ' childNodes=' + (el.childNodes?el.childNodes.length:0) + ' rows={' + rows.join(',') + '}');
        });
        out.push('window._olsr_links=' + (window._olsr_links? window._olsr_links.length : 0) + '  _logLoaded=' + (window._logLoaded?1:0) + '  _statusLoaded=' + (window._statusLoaded?1:0));
        o.textContent = out.join('\n');
      } catch(e) { /* ignore */ }
    }
    update();
    o._interval = setInterval(update, 1500);
  }
  if (window._uiDebug) {
    if (document.readyState === 'complete' || document.readyState === 'interactive') createDebugOverlay();
    else document.addEventListener('DOMContentLoaded', createDebugOverlay);
  }
})();