import json, re, os
# Builds the browser-only online demo (deploy/vercel/index.html) from the app's public/ and lib/ files.
# Run from anywhere: python3 deploy/online-demo/assemble.py
HERE = os.path.dirname(os.path.abspath(__file__))
L = os.path.join(HERE, '..', '..') + '/'
def rd(p): return open(p if os.path.isabs(p) else os.path.join(HERE, p), encoding='utf-8').read()
def lib(name, code):
    return f"__mods[{json.dumps(name)}] = function (module, exports, require, Buffer) {{\n{code}\n}};\n"
libs = "const __mods = {};\n"
libs += lib('playbooks', rd(L+'lib/playbooks.js'))
libs += lib('regulations', rd(L+'lib/regulations.js'))
libs += lib('qr', rd(L+'lib/qr.js'))
libs += """const __LIB = {};
(function () {
  const req = (n) => { if (n === 'node:crypto') return { randomInt: (m) => crypto.getRandomValues(new Uint32Array(1))[0] % m }; throw new Error('no module ' + n); };
  const Buf = { from: (t) => new TextEncoder().encode(t) };
  for (const [k, f] of Object.entries(__mods)) { const m = { exports: {} }; f(m, m.exports, req, Buf); __LIB[k] = m.exports; }
})();
"""
seed = "const __SEED = " + rd('seed.json') + ";\n"
def script(code): return "<script>\n" + code.replace('</', '<\\/') + "\n</script>\n"
css = rd(L+'public/app.css') + "\n" + rd('demo.css')
favicon = rd(L+'public/favicon.svg')
import base64
fav = 'data:image/svg+xml;base64,' + base64.b64encode(favicon.encode()).decode()
html = f"""<title>WINDX Incident Command</title>
<meta name="claude:viewport-fit-sides" content="cover">
<link rel="icon" href="{fav}">
<style>
{css}
</style>
<div id="app"><div class="boot">Unlocking WINDX…</div></div>
<div id="modal-root"></div>
<div id="toasts" aria-live="polite"></div>
""" + script(seed + libs) + script(rd('backend.js')) + script(rd(L+'public/core.js')) + script(rd(L+'public/app.js')) + script(rd(L+'public/assistant.js')) + script(rd(L+'public/replay.js')) + script(rd('demo-ui.js'))
page = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n'
        '<meta name="robots" content="noindex">\n</head>\n<body>\n' + html + '\n</body>\n</html>\n')
open(os.path.join(L, 'deploy', 'vercel', 'index.html'), 'w', encoding='utf-8').write(page)
print(len(html))
