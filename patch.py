import re

content = open('frontend/index.html', 'r', encoding='utf-8').read()

new_chunk_1 = """const API_BASE = "http://localhost:8000";

// ── Demo Trigger ──
let cinematicEvents = [];
async function triggerDemo() {
  showToast('⚡ TRIGGERING DEMO', 'Initializing Employee 4471 scenario...');
  try {
    const res = await fetch(`${API_BASE}/api/demo/trigger`, { method: 'POST' });
    const data = await res.json();
    if (data.success && data.cinematic_data) {
      cinematicEvents = data.cinematic_data.events.map(e => ({
        time: e.time,
        type: e.type,
        icon: e.type === 'normal' ? '🟢' : (e.type === 'critical' || e.type === 'freeze' || e.type === 'evidence' ? '🔴' : '🟡'),
        desc: e.desc,
        score: e.score
      }));
      openCinematic();
    }
  } catch (err) {
    showToast('❌ ERROR', 'Could not connect to backend.');
    console.error(err);
  }
}

// ── Cinematic Fraud Story ──
let cinematicStep = 0;
let cinematicTimer = null;

function openCinematic() {
  cinematicStep = 0;
  document.getElementById('cin-modal').classList.add('open');
  document.getElementById('cin-timeline').innerHTML = '';
  document.getElementById('cin-score-display').textContent = '12';
  document.getElementById('cin-score-display').style.color = 'var(--teal)';
  document.getElementById('cin-status').textContent = 'Live cinematic initiated...';
  document.getElementById('cin-status').style.color = 'var(--teal)';
  if (cinematicTimer) clearInterval(cinematicTimer);
  cinematicTimer = setInterval(runCinematicStep, 1000);
}

function runCinematicStep() {
  if (cinematicStep >= cinematicEvents.length) {
    clearInterval(cinematicTimer);
    document.getElementById('cin-status').textContent = '🚨 FRAUD DETECTED — Evidence secured in blockchain';
    document.getElementById('cin-status').style.color = 'var(--red)';
    showToast('🚨 CINEMATIC COMPLETE', 'Employee 4471 — 96/100 CRITICAL · Account frozen · STR filed');
    return;
  }
  const ev = cinematicEvents[cinematicStep];
  const tl = document.getElementById('cin-timeline');
  const color = ev.type === 'normal' ? 'var(--teal)' : ev.type === 'warning' ? 'var(--gold)' : 'var(--red)';
  const row = document.createElement('div');
  row.style.cssText = 'display:flex;gap:12px;padding:8px 0;border-bottom:1px solid var(--border);animation:fadeIn 0.3s ease';
  row.innerHTML = `
    <div style="font-size:11px;min-width:68px;font-family:'IBM Plex Mono',monospace;color:var(--text3);flex-shrink:0">${ev.time}</div>
    <div style="font-size:14px;flex-shrink:0">${ev.icon || '•'}</div>
    <div style="flex:1;font-size:12px;color:${color}">${ev.desc}</div>
    <div style="font-size:13px;font-weight:700;font-family:'IBM Plex Mono',monospace;color:${color};min-width:30px;text-align:right">${ev.score}</div>
  `;
  tl.appendChild(row);
  tl.scrollTop = tl.scrollHeight;
  const scoreEl = document.getElementById('cin-score-display');
  scoreEl.textContent = ev.score;
  scoreEl.style.color = color;
  document.getElementById('cin-status').textContent = ev.desc;
  document.getElementById('cin-status').style.color = color;
  cinematicStep++;
}

function closeCinematic() {
  if (cinematicTimer) clearInterval(cinematicTimer);
  document.getElementById('cin-modal').classList.remove('open');
}"""

content = re.sub(r'// ── Demo Trigger ──.*?function closeCinematic\(\) \{.*?\}', new_chunk_1, content, flags=re.DOTALL)

new_chunk_2 = """// ── XAI Slider ──
async function updateXAI() {
  const s1 = parseInt(document.getElementById('s1').value);
  const s2 = parseInt(document.getElementById('s2').value);
  const s3 = parseInt(document.getElementById('s3').value);
  const s4 = parseInt(document.getElementById('s4').value);

  const times = ['12AM','1AM','2AM','3AM','4AM','5AM','6AM','7AM','8AM','9AM','10AM','11AM','12PM','1PM','2PM','3PM','4PM','5PM','6PM','7PM','8PM','9PM','10PM','11PM'];
  document.getElementById('s1-val').textContent = times[s1];
  document.getElementById('s2-val').textContent = s2.toLocaleString();
  document.getElementById('s3-val').textContent = '₹' + s3 + 'L';

  const ipLabels = ['Unknown','Unknown','Unknown','Low','Low','Partial','Partial','Known','Known','Registered','Registered'];
  document.getElementById('s4-val').textContent = ipLabels[s4];

  try {
    const res = await fetch(`${API_BASE}/api/counterfactual/EMP4471?login_time=${s1}&records=${s2}&txn_amount=${s3 * 100000}`);
    const data = await res.json();
    
    document.getElementById('s1-impact').textContent = data.reasons[0].split(': ')[1] || '';
    document.getElementById('s2-impact').textContent = data.reasons[1].split(': ')[1] || '';
    document.getElementById('s3-impact').textContent = data.reasons[2].split(': ')[1] || '';
    document.getElementById('s4-impact').textContent = data.reasons[3] && data.reasons[3].split(': ')[1] || '';

    const score = data.score;
    const scoreEl = document.getElementById('xai-score');
    scoreEl.textContent = score;
    scoreEl.style.color = score >= 80 ? 'var(--red)' : score >= 50 ? 'var(--gold)' : 'var(--teal)';

    const cl = document.getElementById('clearance-text');
    const thresPass = score < 40 ? `<span style="color:var(--teal)">✓ Score is now below alert threshold (40). This employee would NOT be flagged with these parameters.</span>` : `To drop below threshold, reduce: login time to business hours, records accessed below 200, transfer below ₹10L, and use a registered device.`;
    cl.innerHTML = `Current score: <span style="color:${score>=80?'var(--red)':score>=50?'var(--gold)':'var(--teal)'};font-weight:700;font-family:'IBM Plex Mono',monospace">${score}/100</span> — ${data.risk_level}<br><br>${thresPass}<br><br><span style="color:var(--teal)">This is legally defensible XAI evidence.</span>`;
  } catch(e) { console.error(e); }
}

// ── DeceptionGuard ──
let trigCount = 0;
async function simulateTrap() {
  try {
    await fetch(`${API_BASE}/api/deception-guard/simulate-access?employee_id=EMP4471`, { method: 'POST' });
    const randomMA = Math.floor(Math.random() * 10);
    const maEl = document.getElementById('ma-' + randomMA);
    if(maEl) {
      maEl.classList.add('triggered');
      maEl.querySelector('.ma-status').innerHTML = '<span style="color:var(--red)">🚨 ACCESSED</span>';
      maEl.style.borderColor = 'var(--red)';
    }

    trigCount++;
    document.getElementById('trig-count').textContent = trigCount;
    document.getElementById('trap-result').style.display = 'block';
    document.getElementById('trap-btn').textContent = 'Triggered ✓';
    document.getElementById('trap-btn').disabled = true;
    document.getElementById('trap-btn').style.opacity = '0.5';

    showToast('🚨 DECEPTIONGUARD TRIGGERED', '100/100 Fraud Confirmed · Evidence generated');
  } catch(e) { console.error(e); }
}

// ── Evidence Generate ──
async function generateEvidence() {
  showToast('⚡ GENERATING REPORT', 'Compiling evidence and contacting FIU-IND...');
  try {
    const res = await fetch(`${API_BASE}/api/evidence/EMP4471`);
    const data = await res.json();
    setTimeout(() => {
        showToast('✓ EVIDENCE READY', `Hash: ${data.evidence_hash.substring(0,25)}...`);
    }, 2000);
  } catch(e) { console.error(e); }
}

// ── Init animations & WS ──
window.addEventListener('load', async () => {
  setTimeout(() => showToast('⚡ VAULTMIND ACTIVE', '8 agents connected · Listening for live events...'), 1000);
  
  // Dashboard Init 
  try {
    const res = await fetch(`${API_BASE}/api/dashboard`);
    const d = await res.json();
    console.log('Dashboard Data Loaded', d.stats);
  } catch(e) {}

  // WebSocket
  try {
      const ws = new WebSocket('ws://localhost:8000/ws/alerts');
      ws.onmessage = (event) => {
        const msg = JSON.parse(event.data);
        if(msg.type === 'alerts_update') {
          console.log('Live Alert Push Received', msg.data);
          // Re-render the Alert List HTML if needed.
        }
      };
      ws.onclose = () => console.log('WebSocket closed');
  } catch(e) {}
});"""

content = re.sub(r'// ── XAI Slider ──.*?}\);', new_chunk_2, content, flags=re.DOTALL)

open('frontend/index.html', 'w', encoding='utf-8').write(content)
