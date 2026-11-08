'use strict';
/* Helper box for the online demo: live sign-in codes, one-click sign in, reset. */
(function () {
  const D = window.__lifeboatDemo;
  const box = document.createElement('aside');
  box.id = 'demo-box';
  box.setAttribute('aria-label', 'Online demo helper');
  document.body.append(box);
  let open = true, codes = [], wasSignedIn = null;
  const signedIn = () => !!(typeof S !== 'undefined' && S.me);
  function draw() {
    const inApp = signedIn();
    if (inApp !== wasSignedIn) { open = !inApp; wasSignedIn = inApp; }
    const left = 30 - (Math.floor(Date.now() / 1000) % 30);
    box.className = 'demo-box ' + (inApp ? 'in-app' : 'on-login') + (open ? ' open' : '');
    const rows = codes.map(([u, r, c]) => `<div class="demo-row"><div><b>${u}</b><span>${r}</span></div><code data-code="${u}">${c}</code>${inApp ? '' : `<button type="button" data-demo-signin="${u}">Sign in</button>`}</div>`).join('');
    box.innerHTML = open
      ? `<div class="demo-head"><b>Online demo</b><button type="button" class="demo-x" data-demo-toggle aria-label="Minimize">–</button></div>
         <p>Password for everyone: <code>lifeboat-demo-2026</code><br>6-digit codes (new ones in <span data-left>${left}</span>s):</p>
         ${rows || '<p>Loading codes…</p>'}
         <p class="demo-tip">${inApp ? 'Tip: open this page in a second browser tab, sign in as <b>dana</b>, and send messages between the two tabs.' : 'Click <b>Sign in</b> next to a person, or type the details yourself.'}</p>
         <button type="button" class="demo-reset" data-demo-reset>Reset demo data</button>`
      : `<button type="button" class="demo-pill" data-demo-toggle>Demo Codes</button>`;
  }
  box.addEventListener('click', async (e) => {
    const t = e.target.closest('button'); if (!t) return;
    if (t.hasAttribute('data-demo-toggle')) { open = !open; tick(); }
    else if (t.hasAttribute('data-demo-reset')) {
      if (t.dataset.confirm) D.reset(); else { t.dataset.confirm = '1'; t.textContent = 'Click again to erase all demo changes'; }
    } else if (t.dataset.demoSignin) {
      t.disabled = true; t.textContent = '…';
      await D.signIn(t.dataset.demoSignin);
      setTimeout(() => { t.disabled = false; t.textContent = 'Sign in'; }, 1500);
    }
  });
  // Only redraw the whole box when something structural changes; otherwise just update numbers,
  // so buttons are never swapped out from under a click.
  let shape = '';
  function tick() {
    const key = signedIn() + '|' + open + '|' + codes.length;
    if (key !== shape) { shape = key; draw(); return; }
    const left = box.querySelector('[data-left]');
    if (left) left.textContent = 30 - (Math.floor(Date.now() / 1000) % 30);
    for (const [u, , c] of codes) { const el = box.querySelector(`[data-code="${u}"]`); if (el && el.textContent !== c) el.textContent = c; }
  }
  // The Wallboard is a big-screen view, so the demo helper stays out of it.
  const onWall = () => location.hash.startsWith('#/wall');
  function placeBox() { box.hidden = onWall(); }
  addEventListener('hashchange', placeBox);
  placeBox();
  async function refreshCodes() { try { codes = await D.codes(); } catch { codes = []; } tick(); }
  refreshCodes();
  setInterval(() => { if (Date.now() / 1000 % 30 < 1.2 || Date.now() / 1000 % 3 < 1) refreshCodes(); else tick(); }, 1000);
})();

// Exports (CSV / JSON) go through the viewer's download prompt, since plain download links are blocked here.
(function () {
  if (!window.claude) return; // on a normal website the regular download links work
  let dl = null;
  if (window.claude.use) window.claude.use('downloads').then((d) => { dl = d; });
  downloadText = async function (name, text) {
    if (!dl) { toast('Downloads are not available in this view.', 'err'); return; }
    try { await dl.save({ filename: name, data: text }); toast('Saved ' + name, 'ok'); }
    catch (e) { if (e && e.code !== 'declined') toast('Download did not start (' + (e.code || 'error') + ').', 'err'); }
  };
})();
