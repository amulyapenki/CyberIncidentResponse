'use strict';
/* Attack Replay: a simulated, minute-by-minute replay of how an attack on the protected
   organization unfolded. Uses dummy data so teams can walk through it backward and forward
   and see what could have prevented each step. Shown on the Wallboard. */
(function () {
  // ---------------------------------------------------------------- dummy data
  const LANES = [
    { id: 'attacker', label: 'Attacker' },
    { id: 'network', label: 'Network' },
    { id: 'data', label: 'Data' },
    { id: 'defense', label: 'Security team' },
  ];
  // Times are minutes after midnight, local time.
  const T = (h, m) => h * 60 + m;
  const EVENTS = [
    { t: T(8, 42), lane: 'attacker', title: 'Phishing email delivered', what: 'An email with "Invoice_Nov.docm" reaches three inboxes in Accounts Payable. It looks like it comes from a known vendor.', prevent: 'Attachment sandboxing, or blocking macro-enabled Office files from outside senders.' },
    { t: T(9, 0), lane: 'attacker', key: true, title: 'Employee opens a suspicious attachment', what: 'An accounts payable clerk opens the invoice and clicks "Enable content". A hidden macro installs a backdoor on workstation WS14.', prevent: 'Block Office macros in files from the internet, and train staff to report unexpected invoices.' },
    { t: T(9, 7), lane: 'network', title: 'Backdoor calls home', what: 'WS14 starts contacting update-msedge-cdn.com every 60 seconds. The domain was registered two days ago.', prevent: 'DNS filtering that blocks newly registered domains.' },
    { t: T(9, 15), lane: 'network', key: true, title: 'Unusual network activity begins', what: 'WS14 scans the internal network (10.20.0.0/16), looking for file servers and domain controllers.', prevent: 'Network segmentation, and an EDR rule that alerts on internal scanning from a workstation.' },
    { t: T(9, 22), lane: 'attacker', title: 'Administrator password stolen', what: 'The attacker pulls saved credentials from WS14 memory, including a domain admin account that had signed in to that machine.', prevent: 'Never sign in to workstations with admin accounts; turn on Credential Guard and unique local admin passwords.' },
    { t: T(9, 30), lane: 'data', key: true, title: 'Sensitive data is accessed', what: 'Using the stolen admin account, the attacker opens FS02 \\\\clinical\\scans, which holds scanned patient intake forms.', prevent: 'Least-privilege access to patient files, and alerts when an admin account reads clinical shares.' },
    { t: T(9, 41), lane: 'data', title: 'Patient records packed for theft', what: '18,400 patient records are compressed into a single 380 GB archive on FS02.', prevent: 'File-integrity monitoring that flags large archives created on file servers.' },
    { t: T(9, 48), lane: 'network', title: 'Data leaves the network', what: 'An upload to mega.nz starts at more than 300 MB per minute. This is the exfiltration.', prevent: 'Egress filtering and data loss prevention that blocks bulk uploads to file-sharing sites.' },
    { t: T(9, 52), lane: 'defense', title: 'Alert fires but is not triaged', what: 'EDR raises a medium alert, "Suspicious rclone execution on FS02". Nobody is watching the queue overnight.', prevent: '24/7 alert monitoring, or automatic isolation for high-risk detections.' },
    { t: T(10, 0), lane: 'defense', key: true, title: 'Security team detects the incident', what: 'The on-call analyst connects the EDR alert with the outbound traffic spike and calls the incident lead.', prevent: 'Detection here was 60 minutes after the attachment was opened. Earlier alerts at 9:15 or 9:30 could have cut that to minutes.' },
    { t: T(10, 6), lane: 'defense', title: 'Infected machines isolated', what: 'WS14 and FS02 are disconnected from the network but left powered on to preserve evidence.', prevent: 'This step went right: isolate, do not power off.' },
    { t: T(10, 12), lane: 'network', title: 'Outbound traffic back to normal', what: 'The upload stops. Roughly 380 GB left the network in 18 minutes.', prevent: 'Each minute of faster detection would have kept about 20 GB of patient data inside.' },
    { t: T(10, 20), lane: 'defense', title: 'Incident declared in WINDX', what: 'The team declares BLACK HERON, moves all communication to WINDX, and the legal deadline clocks start.', prevent: 'This step went right: one place for the response, out of the attacker\'s reach.' },
  ];
  const START = T(8, 30), END = T(10, 40);
  // Outbound traffic in MB per minute, one value per minute (simulated).
  const TRAFFIC = [];
  for (let m = START; m <= END; m++) {
    let v = 3 + 1.4 * Math.sin(m / 6) + 0.8 * Math.sin(m / 2.3);
    if (m >= T(9, 7) && m < T(10, 6)) v += 1.2;
    if (m >= T(9, 15) && m < T(9, 28)) v += 26 + 9 * Math.sin(m);
    if (m >= T(9, 30) && m < T(9, 46)) v += 11 + 3 * Math.sin(m / 1.7);
    if (m >= T(9, 48) && m < T(10, 7)) v += 322 + 26 * Math.sin(m / 2.1) + (m - T(9, 48)) * 1.2;
    if (m >= T(10, 7)) v = 2 + 0.7 * Math.sin(m / 3);
    TRAFFIC.push({ t: m, v: Math.max(0.5, Math.round(v * 10) / 10) });
  }

  // ---------------------------------------------------------------- state & helpers
  const st = { sel: 0, playing: false, timer: null, list: false };
  const pad2 = (n) => String(n).padStart(2, '0');
  const clock = (t) => { const h = Math.floor(t / 60), m = t % 60; return `${((h + 11) % 12) + 1}:${pad2(m)} ${h < 12 ? 'AM' : 'PM'}`; };
  const laneOf = (id) => LANES.find((l) => l.id === id);
  const firstKey = EVENTS.find((e) => e.key).t;
  const detected = EVENTS.find((e) => e.title.startsWith('Security team detects')).t;
  const peak = TRAFFIC.reduce((a, b) => (b.v > a.v ? b : a));
  let root = null;

  // ---------------------------------------------------------------- rendering
  function chartSVG(W) {
    const L = 118, R = 18, laneH = 44, top = 30, lanesH = laneH * LANES.length;
    const trafficTop = top + lanesH + 34, trafficH = 120, axisY = trafficTop + trafficH;
    const H = axisY + 30;
    const x = (t) => L + ((t - START) / (END - START)) * (W - L - R);
    const maxV = 400;
    const y = (v) => trafficTop + trafficH - (v / maxV) * trafficH;
    const cur = EVENTS[st.sel];
    const ticks = [];
    for (let t = T(8, 30); t <= END; t += 15) ticks.push(t);
    const area = `M${x(TRAFFIC[0].t)},${y(0)} ` + TRAFFIC.map((p) => `L${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ') + ` L${x(TRAFFIC.at(-1).t)},${y(0)} Z`;
    const line = TRAFFIC.map((p, i) => `${i ? 'L' : 'M'}${x(p.t).toFixed(1)},${y(p.v).toFixed(1)}`).join(' ');
    return html`<svg class="replay-svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Simulated attack timeline from 8:30 to 10:40 AM, with outbound network traffic">
      ${ticks.map((t) => html`<line class="r-grid" x1="${x(t)}" x2="${x(t)}" y1="${top - 6}" y2="${axisY}"/>`)}
      ${LANES.map((l, i) => html`<g>
        <line class="r-lane" x1="${L}" x2="${W - R}" y1="${top + i * laneH + laneH / 2}" y2="${top + i * laneH + laneH / 2}"/>
        <text class="r-label" x="${L - 12}" y="${top + i * laneH + laneH / 2 + 4}" text-anchor="end">${l.label}</text></g>`)}
      <line class="r-detect" x1="${x(detected)}" x2="${x(detected)}" y1="${top - 14}" y2="${axisY}"/>
      <text class="r-detect-label" x="${x(detected) + 6}" y="${top - 16}">Detected ${clock(detected)}</text>
      <rect class="r-gap" x="${x(firstKey)}" y="${top - 6}" width="${x(detected) - x(firstKey)}" height="${lanesH + 6}"/>
      <text class="r-gap-label" x="${(x(firstKey) + x(detected)) / 2}" y="${top + lanesH + 16}" text-anchor="middle">Attacker inside, undetected: ${detected - firstKey} minutes</text>
      <line class="r-cursor" x1="${x(cur.t)}" x2="${x(cur.t)}" y1="${top - 6}" y2="${axisY}"/>
      ${EVENTS.map((e, i) => {
        const li = LANES.findIndex((l) => l.id === e.lane);
        const cy = top + li * laneH + laneH / 2, cx = x(e.t), sel = i === st.sel, past = i <= st.sel;
        return html`<g class="r-ev ${sel ? 'sel' : ''} ${past ? '' : 'future'}" data-i="${i}" tabindex="0" role="button" aria-label="${clock(e.t)}: ${e.title}">
          <circle class="r-hit" cx="${cx}" cy="${cy}" r="14"/>
          <circle class="r-dot lane-${e.lane}" cx="${cx}" cy="${cy}" r="${sel ? 9 : e.key ? 7 : 5}"/>
          ${e.key ? html`<text class="r-key" x="${cx}" y="${cy - 13}" text-anchor="middle">${clock(e.t).replace(' AM', '')}</text>` : ''}
        </g>`;
      })}
      <text class="r-label" x="${L - 12}" y="${trafficTop + trafficH / 2 - 2}" text-anchor="end">Outbound</text>
      <text class="r-sub" x="${L - 12}" y="${trafficTop + trafficH / 2 + 13}" text-anchor="end">MB / minute</text>
      ${[0, 100, 200, 300, 400].map((v) => html`<g><line class="r-grid" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/><text class="r-tick" x="${L + 4}" y="${y(v) - 4}">${v}</text></g>`)}
      <path class="r-area" d="${area}"/>
      <path class="r-line" d="${line}"/>
      <circle class="r-peak" cx="${x(peak.t)}" cy="${y(peak.v)}" r="4"/>
      <text class="r-tick r-peak-label" x="${x(peak.t) - 10}" y="${y(peak.v) - 8}" text-anchor="end">Peak ${Math.round(peak.v)} MB/min</text>
      <line class="r-axis" x1="${L}" x2="${W - R}" y1="${axisY}" y2="${axisY}"/>
      ${ticks.map((t) => html`<text class="r-tick" x="${x(t)}" y="${axisY + 18}" text-anchor="middle">${clock(t).replace(' AM', '').replace(' PM', '')}</text>`)}
      <line class="r-hover hidden" y1="${trafficTop}" y2="${axisY}"/>
      <rect class="r-traffic-hit" x="${L}" y="${trafficTop}" width="${W - L - R}" height="${trafficH}"/>
    </svg>`;
  }

  function draw() {
    if (!root || !root.isConnected) { stop(); return; }
    const W = Math.max(640, Math.floor(root.querySelector('.replay-chart').clientWidth || 900));
    const e = EVENTS[st.sel];
    const lane = laneOf(e.lane);
    setHTML(root.querySelector('.replay-chart'), chartSVG(W));
    setHTML(root.querySelector('.replay-detail'), html`
      <div class="replay-step"><span class="mono">${clock(e.t)}</span><span class="replay-lane" data-lane="${e.lane}">${lane.label}</span><span class="tiny muted">Step ${st.sel + 1} of ${EVENTS.length}${e.t < detected ? ` · ${detected - e.t} min before detection` : e.t > detected ? ` · ${e.t - detected} min after detection` : ' · moment of detection'}</span></div>
      <h3>${e.title}</h3>
      <div class="replay-cols"><div><div class="replay-h">What happened</div><p>${e.what}</p></div>
      <div><div class="replay-h">What could have prevented it</div><p>${e.prevent}</p></div></div>`);
    root.querySelector('[data-r="prev"]').disabled = st.sel === 0;
    root.querySelector('[data-r="next"]').disabled = st.sel === EVENTS.length - 1;
    root.querySelector('[data-r="play"]').textContent = st.playing ? 'Pause' : st.sel === EVENTS.length - 1 ? 'Replay' : 'Play';
    root.querySelector('.replay-range').value = st.sel;
    if (st.list) setHTML(root.querySelector('.replay-table'), html`<table class="t"><thead><tr><th>Time</th><th>Where</th><th>What happened</th><th>What could have prevented it</th></tr></thead><tbody>
      ${EVENTS.map((ev, i) => html`<tr class="${i === st.sel ? 'sel' : ''}"><td class="mono nowrap">${clock(ev.t)}</td><td>${laneOf(ev.lane).label}</td><td><b>${ev.title}</b><div class="small muted">${ev.what}</div></td><td class="small">${ev.prevent}</td></tr>`)}
    </tbody></table>`);
  }

  function go(i) { st.sel = Math.max(0, Math.min(EVENTS.length - 1, i)); draw(); }
  function stop() { st.playing = false; clearInterval(st.timer); st.timer = null; }
  function play() {
    if (st.playing) { stop(); draw(); return; }
    if (st.sel === EVENTS.length - 1) st.sel = 0;
    st.playing = true;
    draw();
    st.timer = setInterval(() => { if (st.sel >= EVENTS.length - 1) { stop(); draw(); return; } go(st.sel + 1); }, 1800);
  }

  function tooltip(evt, text, sub) {
    const tip = root.querySelector('.replay-tip');
    const box = root.querySelector('.replay-chart').getBoundingClientRect();
    tip.replaceChildren();
    const b = document.createElement('b'); b.textContent = text;
    const s = document.createElement('span'); s.textContent = sub;
    tip.append(b, s);
    tip.hidden = false;
    const x = Math.min(evt.clientX - box.left + 14, box.width - 240);
    tip.style.left = Math.max(0, x) + 'px';
    tip.style.top = (evt.clientY - box.top + 14) + 'px';
  }

  // ---------------------------------------------------------------- public
  window.AttackReplay = {
    markup: () => html`<section class="panel replay" aria-label="Attack replay">
      <div class="panel-head"><h2 class="replay-title">Attack Replay</h2>
        <div class="row"><button type="button" class="btn sm" data-r="list">List view</button></div></div>
      <div class="replay-stats">
        <div><b>${detected - firstKey} min</b><span>Attacker inside before detection</span></div>
        <div><b>${Math.round(peak.v)} MB/min</b><span>Peak outbound traffic</span></div>
        <div><b>18,400</b><span>Patient records exposed</span></div>
        <div><b>8 min</b><span>Alert went unnoticed</span></div>
      </div>
      <div class="replay-controls">
        <button type="button" class="btn sm" data-r="prev" aria-label="Previous step">‹ Back</button>
        <button type="button" class="btn sm primary" data-r="play">Play</button>
        <button type="button" class="btn sm" data-r="next" aria-label="Next step">Forward ›</button>
        <input type="range" class="replay-range" min="0" max="${EVENTS.length - 1}" step="1" value="0" aria-label="Step through the attack">
      </div>
      <div class="replay-wrap"><div class="replay-chart"></div><div class="replay-tip" hidden></div></div>
      <div class="replay-detail" aria-live="polite"></div>
      <div class="replay-table table-wrap"></div>
    </section>`,
    mount(el) {
      root = el;
      if (!root) return;
      root.addEventListener('click', (e) => {
        const b = e.target.closest('[data-r]');
        if (b) {
          const r = b.dataset.r;
          if (r === 'prev') { stop(); go(st.sel - 1); }
          if (r === 'next') { stop(); go(st.sel + 1); }
          if (r === 'play') play();
          if (r === 'list') { st.list = !st.list; b.textContent = st.list ? 'Hide list' : 'List view'; if (!st.list) setHTML(root.querySelector('.replay-table'), ''); draw(); }
          return;
        }
        const ev = e.target.closest('.r-ev');
        if (ev) { stop(); go(Number(ev.dataset.i)); }
      });
      root.addEventListener('keydown', (e) => {
        const ev = e.target.closest?.('.r-ev');
        if (ev && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); stop(); go(Number(ev.dataset.i)); }
        if (e.target.closest?.('.replay') && !e.target.matches('input, textarea') && (e.key === 'ArrowLeft' || e.key === 'ArrowRight')) { e.preventDefault(); stop(); go(st.sel + (e.key === 'ArrowRight' ? 1 : -1)); }
      });
      root.addEventListener('input', (e) => { if (e.target.matches('.replay-range')) { stop(); go(Number(e.target.value)); } });
      root.addEventListener('pointermove', (e) => {
        const ev = e.target.closest('.r-ev');
        const hover = root.querySelector('.r-hover');
        if (ev) { const d = EVENTS[Number(ev.dataset.i)]; tooltip(e, `${clock(d.t)}  ${d.title}`, laneOf(d.lane).label + ' · click for details'); hover?.classList.add('hidden'); return; }
        if (e.target.matches('.r-traffic-hit')) {
          const r = e.target.getBoundingClientRect();
          const t = Math.round(START + ((e.clientX - r.left) / r.width) * (END - START));
          const p = TRAFFIC.find((q) => q.t === t) || TRAFFIC.at(-1);
          const svg = root.querySelector('.replay-svg');
          const scale = svg.viewBox.baseVal.width / svg.getBoundingClientRect().width;
          const vx = (e.clientX - svg.getBoundingClientRect().left) * scale;
          if (hover) { hover.setAttribute('x1', vx); hover.setAttribute('x2', vx); hover.classList.remove('hidden'); }
          tooltip(e, `${p.v} MB/min`, `Outbound traffic at ${clock(p.t)}`);
          return;
        }
        root.querySelector('.replay-tip').hidden = true;
        hover?.classList.add('hidden');
      });
      root.addEventListener('pointerleave', () => { root.querySelector('.replay-tip').hidden = true; });
      draw();
    },
    redraw: () => draw(),
  };
  addEventListener('resize', () => { if (root?.isConnected) draw(); });
})();
