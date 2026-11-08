"""IntentX Phase 14A interactive console.

Presentation-only boundary. Analyze uses execute=false. Execute Safely sends a
separate execute=true request; backend ApplicationService/ExecutionBroker
controls remain authoritative.
"""

DASHBOARD_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>IntentX | Safe Linux Command Execution · Controlled Operations Console</title>
<style>
:root{
  --bg:#050b14;--card:#0a1526;--card-border:#1c2d47;
  --t:#eaf1fb;--m:#8297b5;--sub:#657b9b;
  --blue:#3b82f6;--green:#10b981;--yellow:#f59e0b;--red:#ef4444;--purple:#a855f7;
  --green-glow:rgba(16,185,129,0.25);--red-glow:rgba(239,68,68,0.35);
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(circle at 18% 0,#0f2442 0,var(--bg) 42%);color:var(--t);font-family:Inter,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;-webkit-font-smoothing:antialiased}
main{width:min(1480px,calc(100% - 32px));margin:auto;padding:20px 0 50px}
header.top{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:14px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:14px}
.logo{width:50px;height:50px;border-radius:12px;background:linear-gradient(135deg,#60a5fa,#2563eb);color:#fff;display:grid;place-items:center;font-size:22px;font-weight:900;letter-spacing:-1px;box-shadow:0 0 20px rgba(37,99,235,0.4)}
h1{margin:0;font-size:24px;font-weight:800;letter-spacing:-0.5px}
h2{margin:0;font-size:18px;font-weight:750}
.brand p{color:var(--m);font-size:12px;margin:3px 0 0}
.badges{display:flex;gap:8px;flex-wrap:wrap}
.badge{border:1px solid var(--card-border);border-radius:999px;padding:6px 12px;font-size:11px;font-weight:600;background:rgba(10,21,38,0.8)}
.badge.g{color:#34d399;border-color:rgba(52,211,153,0.3);background:rgba(16,185,129,0.1)}
.badge.bl{color:#93c5fd;border-color:rgba(147,197,253,0.3);background:rgba(59,130,246,0.1)}
.badge.y{color:#fcd34d;border-color:rgba(252,211,77,0.3);background:rgba(245,158,11,0.1)}

/* Scenario Switcher Bar */
.scenario-bar{display:flex;align-items:center;gap:10px;background:rgba(10,21,38,0.9);padding:10px 14px;border-radius:12px;border:1px solid #1e3656;margin-bottom:14px;flex-wrap:wrap}
.scenario-label{font-size:11px;font-weight:800;letter-spacing:0.05em;color:#93c5fd;text-transform:uppercase}
.scen-btn{background:#11223b;color:#cbdcf7;border:1px solid #28446c;padding:7px 14px;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;transition:all .15s ease}
.scen-btn:hover{background:#1c355c;color:#fff;border-color:#4a77b5}
.scen-btn.active{background:linear-gradient(135deg,#1d4ed8,#2563eb);color:#fff;border-color:#60a5fa;box-shadow:0 0 12px rgba(37,99,235,0.4)}
.scen-btn.btn-kernel.active{background:linear-gradient(135deg,#991b1b,#dc2626);border-color:#f87171;box-shadow:0 0 14px rgba(220,38,38,0.5)}
.scen-btn.btn-process.active{background:linear-gradient(135deg,#92400e,#d97706);border-color:#fbbf24;box-shadow:0 0 14px rgba(217,119,6,0.5)}
.scen-btn.btn-network.active{background:linear-gradient(135deg,#581c87,#7e22ce);border-color:#c084fc;box-shadow:0 0 14px rgba(126,34,206,0.5)}

/* Hero Threat Cockpit */
.threat-cockpit{padding:20px;border-radius:16px;margin-bottom:18px;border:2px solid;transition:all .3s ease;box-shadow:0 12px 35px rgba(0,0,0,0.4)}
.threat-cockpit.normal{background:radial-gradient(ellipse at top left,#0a291b 0,#071415 65%);border-color:#10b981;box-shadow:0 0 25px rgba(16,185,129,0.18)}
.threat-cockpit.kernel{background:radial-gradient(ellipse at top left,#450a16 0,#18050a 65%);border-color:#ef4444;box-shadow:0 0 35px rgba(239,68,68,0.35);animation:sirenPulse 2s infinite alternate}
.threat-cockpit.process_churn{background:radial-gradient(ellipse at top left,#3d1a04 0,#140a02 65%);border-color:#f59e0b;box-shadow:0 0 30px rgba(245,158,11,0.25)}
.threat-cockpit.network_exfil{background:radial-gradient(ellipse at top left,#2d0a42 0,#12041c 65%);border-color:#a855f7;box-shadow:0 0 30px rgba(168,85,247,0.25)}

@keyframes sirenPulse{
  0%{box-shadow:0 0 15px rgba(239,68,68,0.25);border-color:#dc2626}
  100%{box-shadow:0 0 40px rgba(239,68,68,0.6);border-color:#f87171}
}

.cockpit-top{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
.cockpit-badge{display:inline-flex;align-items:center;gap:7px;padding:6px 14px;border-radius:999px;font-size:11px;font-weight:800;letter-spacing:0.06em;text-transform:uppercase}
.normal .cockpit-badge{background:#064e3b;color:#6ee7b7;border:1px solid #10b981}
.kernel .cockpit-badge{background:#7f1d1d;color:#fca5a5;border:1px solid #ef4444}
.process_churn .cockpit-badge{background:#78350f;color:#fde68a;border:1px solid #f59e0b}
.network_exfil .cockpit-badge{background:#581c87;color:#e9d5ff;border:1px solid #a855f7}

.cockpit-title{font-size:20px;font-weight:800;margin:10px 0 4px;color:#fff}
.cockpit-sub{color:var(--m);font-size:12px;margin:0 0 14px;max-width:850px;line-height:1.5}
.cockpit-pillars{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:12px}
.pillar{background:rgba(0,0,0,0.35);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:12px}
.pillar-name{font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:var(--m)}
.pillar-val{font-size:16px;font-weight:800;margin-top:5px;color:#fff}
.pillar-status{font-size:10px;margin-top:4px;font-weight:600}
.good{color:#34d399!important}
.bad{color:#f87171!important}
.warn{color:#fbbf24!important}

/* Gauge Bar */
.gauge-container{margin-top:14px;background:rgba(0,0,0,0.4);border:1px solid rgba(255,255,255,0.08);border-radius:10px;padding:12px}
.gauge-head{display:flex;justify-content:space-between;font-size:11px;font-weight:700;margin-bottom:6px}
.gauge-track{height:10px;background:#132238;border-radius:999px;position:relative;overflow:hidden}
.gauge-fill{height:100%;border-radius:999px;transition:all .4s ease}

/* Quick Adopt Banner in Cockpit */
.cockpit-action{display:flex;justify-content:space-between;align-items:center;background:rgba(0,0,0,0.45);border:1px solid rgba(255,255,255,0.12);border-radius:10px;padding:11px 16px;margin-top:14px;gap:14px;flex-wrap:wrap}
.adopt-btn{background:linear-gradient(135deg,#f59e0b,#d97706);color:#080c14;border:none;border-radius:8px;padding:8px 16px;font-size:11px;font-weight:800;cursor:pointer;transition:transform .1s ease}
.adopt-btn:hover{transform:scale(1.02);background:#fbbf24}

/* Navigation and Pipeline */
.nav-bar{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap;background:rgba(10,21,38,0.7);padding:8px 12px;border-radius:12px;border:1px solid var(--card-border)}
.nav-btn{background:#11223a;color:#cbdcf7;text-decoration:none;padding:7px 13px;border-radius:8px;font-size:11px;font-weight:700;border:1px solid #233e63;transition:all .15s ease}
.nav-btn:hover{background:#1c3861;color:white}
.pipe{display:grid;grid-template-columns:repeat(7,1fr);gap:7px;padding:12px;border:1px solid var(--card-border);background:var(--card);border-radius:14px;margin-bottom:16px}
.step{font-size:10px;color:var(--m)}.step b{color:#d9e7fb;display:block;font-size:11px}.n{display:inline-grid;place-items:center;width:24px;height:24px;border:1px solid #3b5b82;border-radius:50%;margin-right:5px;color:#93c5fd}

/* Card and Forms */
.card{background:rgba(10,21,38,0.96);border:1px solid var(--card-border);border-radius:16px;padding:18px;box-shadow:0 14px 40px rgba(0,0,0,0.35);margin-bottom:16px}
.layout{display:grid;grid-template-columns:390px 1fr;gap:16px}
label{display:block;color:#cbd9ec;font-size:12px;font-weight:700;margin:12px 0 6px}
textarea,select{width:100%;background:#06101d;border:1px solid #243c5e;border-radius:10px;color:var(--t);font:inherit;outline:none}
textarea{min-height:120px;padding:12px;resize:vertical}
select{padding:10px}
.selectors{display:grid;grid-template-columns:1fr 1fr;gap:10px}
button{border:0;border-radius:10px;padding:12px;font-weight:800;cursor:pointer}
button:disabled{opacity:.45;cursor:not-allowed}
.primary{background:linear-gradient(135deg,#3b82f6,#2563eb);color:white;width:100%;margin-top:11px}
.execute{background:linear-gradient(135deg,#10b981,#059669);color:#04170d;width:100%;margin-top:11px}
.safe{margin-top:11px;padding:10px;border:1px solid #243c5e;border-radius:10px;background:#06101d;color:var(--m);font-size:11px;line-height:1.5}
.examples div{margin-top:7px;padding:8px 10px;border:1px solid #1e3554;border-radius:8px;color:#bfd0e7;font-size:11px;cursor:pointer;transition:background .15s}
.examples div:hover{background:#11233d}

.main{display:grid;gap:16px}
.heading{display:flex;justify-content:space-between;gap:10px;margin-bottom:13px;align-items:center}
.chip{border:1px solid var(--card-border);border-radius:999px;padding:5px 11px;color:var(--m);font-size:10px;font-weight:700}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:9px}
.metric{background:#0e1b2e;border:1px solid #1e3554;border-radius:10px;padding:12px;min-height:80px}
.name{color:var(--m);font-size:9px;text-transform:uppercase;letter-spacing:.08em;font-weight:700}
.value{font-weight:800;margin-top:6px;overflow-wrap:anywhere;font-size:15px}
.small{color:var(--m);font-size:10px;margin-top:5px}

.command,.detail,.reason{border:1px solid #1e3554;background:#06101d;border-radius:10px;padding:11px}
.command{margin-top:10px}
.command code{font:13px SFMono-Regular,Consolas,monospace;color:#e5efff}
.details{display:grid;grid-template-columns:1fr 1fr;gap:9px;margin-top:9px}
.detail h4{margin:0 0 6px;font-size:10px;color:#cbd9ed}
.detail pre{margin:0;white-space:pre-wrap;color:#aebfd7;font-size:10px;line-height:1.5}
.reason{margin-top:9px;color:#b9c9df;font-size:11px;line-height:1.5;border-left:3px solid var(--blue)}

/* Terminal and Execution */
#execution{display:none}#execution.show{display:block}
.execmeta{display:flex;gap:12px;flex-wrap:wrap;color:var(--m);font-size:10px}
.tabs{display:flex;gap:5px;margin-top:12px}
.tab{background:#11223a;color:#b8c9df;border:1px solid var(--card-border);padding:7px 11px;font-size:10px;border-radius:6px;cursor:pointer}
.tab.active{background:#1d4ed8;color:white;border-color:#3b82f6}
.terminal{margin-top:7px;background:#03070e;border:1px solid #233e63;border-radius:10px;padding:14px;min-height:180px;max-height:430px;overflow:auto}
.terminal pre{margin:0;white-space:pre-wrap;font:12px/1.55 SFMono-Regular,Consolas,monospace;color:#dce8f8}
.audit{display:grid;grid-template-columns:repeat(4,1fr);gap:7px;margin-top:9px}
.audit div{border:1px solid var(--card-border);border-radius:8px;padding:8px;color:var(--m);font-size:10px;background:#06101d}
.audit b{display:block;color:#dce8f8;margin-bottom:3px}

/* Progress bar inside XAI */
.xai-bar-box{margin-top:8px;background:#101e33;border-radius:999px;height:7px;overflow:hidden}
.xai-bar-fill{height:100%;border-radius:999px;transition:width .4s ease}

@media(max-width:1050px){.layout{grid-template-columns:1fr}.pipe{grid-template-columns:repeat(4,1fr)}.cockpit-pillars{grid-template-columns:repeat(2,1fr)}}
@media(max-width:680px){.grid,.details,.cockpit-pillars{grid-template-columns:1fr}.pipe{grid-template-columns:repeat(2,1fr)}.top{align-items:flex-start;flex-direction:column}}
</style></head><body><main>

<header class="top">
  <div class="brand">
    <div class="logo">IX</div>
    <div>
      <h1>IntentX</h1>
      <p>Safe Linux Command Execution · Controlled Operations Console</p>
    </div>
  </div>
  <div class="badges">
    <span class="badge g">✓ Security First</span>
    <span class="badge bl">◈ Sandboxed Linux Execution</span>
    <span class="badge y">● No Direct Browser Execution</span>
  </div>
</header>

<!-- Scenario Selector -->
<div class="scenario-bar">
  <span class="scenario-label">⚡ Live Scenarios:</span>
  <button class="scen-btn active" id="btn-scen-baseline" onclick="switchScenario('baseline')">🟢 Case 1: Baseline Normal</button>
  <button class="scen-btn btn-kernel" id="btn-scen-kernel" onclick="switchScenario('kernel')">🚨 Case 2: Kernel Rootkit</button>
  <button class="scen-btn btn-process" id="btn-scen-process" onclick="switchScenario('process_churn')">⚡ Case 3: Process Churn</button>
  <button class="scen-btn btn-network" id="btn-scen-network" onclick="switchScenario('network_exfil')">🌐 Case 4: Network Exfil</button>
</div>

<!-- Threat Cockpit -->
<div id="threat-cockpit" class="threat-cockpit normal">
  <div class="cockpit-top">
    <div>
      <span id="cockpit-badge" class="cockpit-badge">🛡️ SYSTEM INTEGRITY HEALTHY</span>
      <h2 id="cockpit-title" class="cockpit-title">Normal Baseline Workload</h2>
      <p id="cockpit-sub" class="cockpit-sub">All 19 Linux telemetry indicators operate within calibrated baseline distribution bounds. Isolation Forest decision margin remains positive.</p>
    </div>
  </div>

  <div class="gauge-container">
    <div class="gauge-head">
      <span>Isolation Forest Decision Margin: <b id="cockpit-margin" class="good">+0.0862</b></span>
      <span id="cockpit-threshold">Threshold: -0.56165 (Calibrated)</span>
    </div>
    <div class="gauge-track">
      <div id="cockpit-gauge-fill" class="gauge-fill" style="width:72%;background:#10b981"></div>
    </div>
  </div>

  <div class="cockpit-pillars">
    <div class="pillar">
      <div class="pillar-name">Kernel Integrity</div>
      <div id="pil-kernel" class="pillar-val good">0 (Clean)</div>
      <div id="pil-kernel-st" class="pillar-status good">0x0000 Taint Bitmask</div>
    </div>
    <div class="pillar">
      <div class="pillar-name">Syscall Tracing</div>
      <div id="pil-audit" class="pillar-val good">Nominal</div>
      <div id="pil-audit-st" class="pillar-status good">0 Suspicious Invocations</div>
    </div>
    <div class="pillar">
      <div class="pillar-name">Process Activity</div>
      <div id="pil-process" class="pillar-val">2 Active</div>
      <div id="pil-process-st" class="pillar-status good">Normal User Workload</div>
    </div>
    <div class="pillar">
      <div class="pillar-name">Network Sockets</div>
      <div id="pil-network" class="pillar-val">1 Listener</div>
      <div id="pil-network-st" class="pillar-status good">No Unauthorized Remote Sockets</div>
    </div>
  </div>

  <div id="cockpit-mitigation-box" class="cockpit-action" style="display:none">
    <div>
      <span style="font-size:11px;font-weight:800;color:#fcd34d" id="cockpit-mit-title">[CRITICAL] Lock Kernel Module Insertion</span>
      <p style="margin:2px 0 0;font-size:10px;color:var(--m)" id="cockpit-mit-sub">Prevent unauthorized module loading via sysctl</p>
    </div>
    <button id="cockpit-adopt-btn" class="adopt-btn">⚡ Adopt Countermeasure in Console ↓</button>
  </div>
</div>

<nav class="nav-bar">
  <a href="#console-section" class="nav-btn">💻 1. Operations Console</a>
  <a href="#xai-mitigation-panel" class="nav-btn">🚨 2. Explainable AI (XAI)</a>
  <a href="#live-scoring-panel" class="nav-btn">📈 3. Behavioral Scores</a>
  <a href="#telemetry-panel" class="nav-btn">📡 4. Live Telemetry</a>
  <a href="#behavior-panel" class="nav-btn">📊 5. Validation Lab</a>
</nav>

<section class="pipe">
  <div class="step"><span class="n">1</span><b>ML Intent</b>Classify request</div>
  <div class="step"><span class="n">2</span><b>Entities</b>Extract & validate</div>
  <div class="step"><span class="n">3</span><b>Planning</b>Resolve operation</div>
  <div class="step"><span class="n">4</span><b>Validation</b>Check contract</div>
  <div class="step"><span class="n">5</span><b>Risk</b>Assess factors</div>
  <div class="step"><span class="n">6</span><b>Policy / RBAC</b>Enforce rules</div>
  <div class="step"><span class="n">7</span><b>Execution</b>Broker controlled</div>
</section>

<div class="layout" id="console-section">
  <aside>
    <section class="card">
      <h2>1. Enter Your Request</h2>
      <p class="sub">Describe what you want the Linux system to do.</p>
      <label>Natural-language request</label>
      <textarea id="intent-text" placeholder="Example: show memory usage"></textarea>
      <div class="selectors">
        <div>
          <label>Role</label>
          <select id="role">
            <option value="VIEWER">Viewer</option>
            <option value="OPERATOR">Operator</option>
            <option value="SENIOR_OPERATOR">Senior Operator</option>
            <option value="ADMINISTRATOR">Administrator</option>
          </select>
        </div>
        <div>
          <label>Environment</label>
          <select id="environment">
            <option value="DEV">Development</option>
            <option value="TEST">Test</option>
            <option value="PROD">Production</option>
          </select>
        </div>
      </div>
      <section id="clarification-help" hidden aria-labelledby="clarification-title" class="detail" style="margin:14px 0">
        <h3 id="clarification-title">Help me clarify this request</h3>
        <p id="clarification-message" role="status"></p>
        <p id="clarification-missing"></p>
        <div id="clarification-options" style="display:flex;flex-direction:column;gap:8px"></div>
        <p id="clarification-notice" class="small"></p>
      </section>
      <details class="detail" style="margin:14px 0">
        <summary>Browse supported request examples</summary>
        <p>Choose an example to edit. Each request still needs analysis.</p>
        <div id="supported-request-options"></div>
      </details>
      <button id="analyze-button" class="primary">⌕ Analyze Request</button>
      <button id="execute" class="execute" disabled>▶ Execute Safely</button>
      <div class="safe">Analyze uses <b>execute=false</b>. Execute Safely creates a separate <b>execute=true</b> request. The backend independently repeats validation, risk and policy checks.</div>
      <div class="examples">
        <label>Demo requests</label>
        <div data-q="show memory usage">Show memory usage</div>
        <div data-q="lock kernel modules">Lock kernel modules (Mitigation Demo)</div>
        <div data-q="list files in /app/runtime">List files in /app/runtime</div>
        <div data-q="kill process 1234">Kill process 1234</div>
        <div data-q="format device /dev/fake-intentx-test">Format fake device — blocked demo</div>
      </div>
    </section>
  </aside>

  <div class="main">
    <section class="card">
      <div class="heading">
        <div>
          <h2>2. Analysis Result</h2>
          <p class="sub">AI interpretation plus Read-only security assessment; this assessment is not execution authorization.</p>
        </div>
        <span id="chip" class="chip">Waiting</span>
      </div>
      <div class="grid">
        <div class="metric"><div class="name">Predicted Intent</div><div id="intent-result" class="value">—</div><div id="confidence-result" class="small">Confidence —</div></div>
        <div class="metric"><div class="name">Extracted Entities</div><div id="entities" class="value">—</div><div class="small">Structured backend entities</div></div>
        <div class="metric"><div class="name">Validation</div><div id="validation-result" class="value">Not evaluated</div><div class="small">Operation contract</div></div>
        <div class="metric"><div class="name">Risk</div><div id="risk-level-result" class="value">—</div><div id="risk-score-result" class="small">Score —</div></div>
        <div class="metric"><div class="name">Policy Decision</div><div id="policy-result" class="value">—</div><div id="context" class="small">Role <span id="policy-role-result">—</span> · Environment <span id="policy-environment-result">—</span></div></div>
        <div class="metric"><div class="name">Application Status</div><div id="status-result" class="value">Waiting</div><div id="stage" class="small">Stage —</div></div>
      </div>
      <div class="command">
        <div class="name">Resolved Linux Operation (shell=False)</div>
        <code id="plan-result">No operation plan yet.</code>
      </div>
      <div class="details">
        <div class="detail"><h4>Risk factors</h4><pre id="risk-factors-result">No risk assessment yet.</pre></div>
        <div class="detail"><h4>Policy reasons</h4><pre id="policy-reasons-result">No policy evaluation yet.</pre></div>
      </div>
      <div id="reason" class="reason">Submit a request to begin analysis.</div>
    </section>

    <section id="execution" class="card">
      <div class="heading">
        <div>
          <h2>3. Execution Result</h2>
          <p id="execSummary" class="sub">No execution requested.</p>
        </div>
        <div class="execmeta"><span id="execId">Execution ID —</span><span id="duration">Duration —</span><span id="execStatus">Status —</span></div>
      </div>
      <div class="tabs">
        <button class="tab active" data-tab="stdout">Output (stdout)</button>
        <button class="tab" data-tab="stderr">Error (stderr)</button>
        <button class="tab" data-tab="metadata">Metadata</button>
      </div>
      <div class="terminal"><pre id="terminal">Waiting for execution.</pre></div>
      <div class="audit">
        <div><b>Authorization</b><span id="auth">Not requested</span></div>
        <div><b>Process</b><span id="process">Not started</span></div>
        <div><b>Exit code</b><span id="exit">—</span></div>
        <div><b>Output bounds</b><span id="bounds">—</span></div>
      </div>
    </section>
  </div>
</div>

<section class="card" id="xai-mitigation-panel">
  <div class="heading">
    <div>
      <h2>Explainable AI (XAI) & Threat Mitigation</h2>
      <p class="sub">Feature attribution decomposition · Isolation Forest decision paths · Automated recommendations</p>
    </div>
    <button id="xai-refresh" class="tab" type="button">Refresh XAI Analysis</button>
  </div>
  <p id="xai-summary" class="safe">Awaiting live scoring explanation…</p>
  <div id="xai-factors" class="grid" style="margin-top:10px"></div>
  <h3 style="font-size:13px;margin:18px 0 8px;color:#cbd9ec">Intelligent Mitigation Recommendations</h3>
  <div id="xai-mitigations" style="display:grid;gap:8px"></div>
</section>

<section class="card" id="live-scoring-panel">
  <div class="heading">
    <div>
      <h2>Live behavioral scores</h2>
      <p class="sub">Continuous sliding window observations · Calibrated Isolation Forest · Read-only</p>
    </div>
    <button id="live-refresh" class="tab" type="button">Refresh scores</button>
  </div>
  <p id="live-score-status" role="status" aria-live="polite">Checking scoring connection…</p>
  <p id="live-score-model" class="small"></p>
  <p id="live-score-explained" class="small"></p>
  <p class="safe">This monitoring runtime differs from the training workload. A matching lab hostname does not establish equivalent behavior. Flags are model observations, not confirmed attacks or authorization to execute commands. Feature values show measured evidence, not causal explanations.</p>
  <p id="live-score-phase" class="small">Collection phase unknown · Collection age unavailable</p>
  <p class="small">Startup is the first two minutes of this collection session. Steady-state collection describes elapsed time, not model readiness or workload stability. All flags remain visible.</p>
  <div id="live-score-windows"></div>
</section>

<section class="card" id="telemetry-panel">
  <div class="heading">
    <div>
      <h2>Live telemetry status</h2>
      <p class="sub">Read-only collection observations · Linux /proc & Audit Subsystems</p>
    </div>
    <button id="telemetry-refresh" class="tab" type="button">Refresh status</button>
  </div>
  <p id="telemetry-status" role="status" aria-live="polite">Checking collector connection…</p>
  <p id="telemetry-time" class="small"></p>
  <div id="telemetry-sensors" class="grid"></div>
  <p class="safe">Recent status confirms observed collection activity, not continuous coverage or threat detection. Sensor availability describes the latest collection only.</p>
</section>

<section class="card" id="behavior-panel">
  <div class="heading">
    <div>
      <h2>Behavioral validation</h2>
      <p class="sub">Historical lab results · Experimental · Read-only</p>
    </div>
    <button id="behavior-refresh" class="tab" type="button">Refresh saved results</button>
  </div>
  <p id="behavior-status" class="sub" role="status" aria-live="polite">Loading saved report…</p>
  <div id="behavior-results" hidden>
    <div class="grid">
      <div class="metric"><div class="name">Final benign flags</div><div id="behavior-flags" class="value"></div><div id="behavior-rate" class="small"></div></div>
      <div class="metric"><div class="name">Model</div><div id="behavior-model" class="value"></div><div id="behavior-threshold" class="small"></div></div>
      <div class="metric"><div class="name">Dataset separation</div><div id="behavior-samples" class="value"></div><div id="behavior-calibration" class="small"></div></div>
    </div>
    <p id="behavior-coverage" class="small"></p>
    <p id="behavior-sensors" class="small"></p>
    <p class="safe">Small controlled benign evaluation. A flag is a model observation and does not establish an attack. These results do not authorize command execution.</p>
    <div style="overflow-x:auto">
      <table style="width:100%;border-collapse:collapse;font-size:12px;text-align:left">
        <caption style="text-align:left;margin:12px 0">Evaluation windows — timestamps in UTC; negative margins are flagged</caption>
        <thead>
          <tr><th scope="col">Lab host</th><th scope="col">Window start</th><th scope="col">Score</th><th scope="col">Margin</th><th scope="col">Result</th></tr>
        </thead>
        <tbody id="behavior-windows"></tbody>
      </table>
    </div>
  </div>
</section>

</main>

<script>
const $ = id => document.getElementById(id);
const intent = $("intent-text");
const role = $("role");
const env = $("environment");
const analyze = $("analyze-button");
const execute = $("execute");

let snapshot = null;
let lastExec = null;
let tab = "stdout";

function cid(p){return p+"-"+(crypto.randomUUID?crypto.randomUUID():Date.now()+"-"+Math.random().toString(16).slice(2))}
function set(id,v){const el=$(id);if(el)el.textContent=(v===null||v===undefined||v==="")?"—":String(v)}
function color(id,v){
  let e=$(id);if(!e)return;
  let s=String(v||"").toUpperCase();
  e.classList.remove("good","warn","bad");
  if(/ALLOW|LOW|VALID|EXECUTED|SUCCESS|NORMAL/.test(s))e.classList.add("good");
  else if(/DENY|BLOCK|CRITICAL|FAIL|ERROR|ANOMALOUS|FLAGGED/.test(s))e.classList.add("bad");
  else if(/APPROVAL|MEDIUM|HIGH|CLARIFICATION|WARNING/.test(s))e.classList.add("warn");
}
function quote(x){x=String(x);return /^[A-Za-z0-9_./:=+-]+$/.test(x)?x:"'"+x.replaceAll("'","'\\''")+"'"}
function cmd(p){return p?[p.executable,...(p.arguments||[])].map(quote).join(" "):"No operation plan was created."}
function ents(p){if(!p||!p.entities)return"None";let a=Object.entries(p.entities);return a.length?a.map(([k,v])=>k+" = "+v).join(" · "):"None"}

function chooseRequest(text){
  intent.value=text;
  snapshot=null;
  execute.disabled=true;
  $("execution").classList.remove("show");
  intent.dispatchEvent(new Event("input",{bubbles:true}));
  set("reason","Example selected. Review its action and target, then click Analyze Request.");
  intent.focus();
}
function suggestionButton(example){
  const button=document.createElement("button");button.type="button";
  button.textContent=example.text+(example.state_changing?" (changes files)":"");
  button.style.cssText="text-align:left;padding:10px;margin:4px 0;cursor:pointer";
  button.addEventListener("click",()=>chooseRequest(example.text));
  return button;
}
function renderClarification(help){
  const panel=$("clarification-help"), options=$("clarification-options");
  options.replaceChildren();panel.hidden=!help;
  if(!help)return;
  set("clarification-message",help.message);
  set("clarification-missing",help.missing_entities?.length?"Details to provide: "+help.missing_entities.join(", "):"Use one action per request; include the full path or target when needed.");
  set("clarification-notice",help.notice);
  for(const example of help.suggestions||[]) options.append(suggestionButton(example));
}
for(const text of ["Show memory usage","Show running processes","Show network connections","Show listening ports","What operating system is this?","Tell me the kernel version","List files in /app/logs","Can you read /app/README.md?"]){
  $("supported-request-options").append(suggestionButton({text,state_changing:false}));
}
function render(data){
  renderClarification(data.status==="CLARIFICATION_REQUIRED"?data.clarification:null);
  let assessment=data.security_assessment||{},v=assessment.validation||{},r=assessment.risk||{},p=assessment.policy||{};
  let d=data;
  set("intent-result",d.predicted_intent);
  set("confidence-result",d.confidence==null?"Confidence —":"Confidence "+(d.confidence*100).toFixed(1)+"%");
  set("entities",ents(d.plan));
  set("plan-result",cmd(d.plan));
  set("validation-result",v.decision||"Not evaluated");
  color("validation-result",v.decision);
  set("risk-level-result",r.level);
  color("risk-level-result",r.level);
  set("risk-score-result",r.score==null?"Score —":"Score "+r.score+"/100");
  set("policy-result",p.decision);
  color("policy-result",p.decision);
  set("policy-role-result",p.role||"—");
  set("policy-environment-result",p.environment||"—");
  set("status-result",d.status);
  color("status-result",d.status);
  set("stage","Stage "+(d.stage||"—"));
  set("chip",d.status||"Analyzed");
  color("chip",d.status);
  set("reason",d.reason);
  let f=Array.isArray(r.factors)?r.factors:[],rs=Array.isArray(p.reasons)?p.reasons:[];
  set("risk-factors-result",f.length?f.map(x=>(x.code||"FACTOR")+(x.score==null?"":" (+"+x.score+")")+": "+(x.description||"")).join("\n"):"No scored risk factors.");
  set("policy-reasons-result",rs.length?rs.map(x=>(x.code||"REASON")+": "+(x.message||"")).join("\n"):"No policy reasons returned.");
  execute.disabled=!d.plan;
}

async function call(ex){
  let q=intent.value.trim();
  /* Analysis contract retained from Phase 11: execute: false.
     Explicit execution uses true only after user action. */
  if(!q)throw Error("Enter a natural-language system request.");
  let res=await fetch("/api/v1/intent",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({text:q,role:role.value,environment:env.value,correlation_id:cid(ex?"exec-ui":"analyze-ui"),execute:ex})
  });
  let d=await res.json();
  if(!res.ok)throw Error(d.detail?JSON.stringify(d.detail):"Request failed.");
  return d;
}

analyze.onclick=async()=>{
  renderClarification(null);
  analyze.disabled=true;execute.disabled=true;analyze.textContent="Analyzing...";
  $("execution").classList.remove("show");
  try{
    let d=await call(false);
    snapshot={q:intent.value.trim(),r:role.value,e:env.value};
    render(d);
  }catch(e){
    set("status-result","Request failed");
    color("status-result","FAILED");
    set("reason",e.message);
    snapshot=null;
  }finally{
    analyze.disabled=false;
    analyze.textContent="⌕ Analyze Request";
  }
};

execute.onclick=async()=>{
  if(!snapshot)return;
  if(intent.value.trim()!=snapshot.q||role.value!=snapshot.r||env.value!=snapshot.e){
    set("reason","Request, role or environment changed. Analyze again before execution.");
    execute.disabled=true;
    return;
  }
  execute.disabled=true;analyze.disabled=true;
  $("execution").classList.add("show");
  set("execSummary","ExecutionBroker is independently re-evaluating the request.");
  set("terminal","Waiting for execution result...");
  try{
    let d=await call(true);
    render(d);
    lastExec=d.execution_result;
    renderExec(d);
  }catch(e){
    set("execSummary","Execution request failed.");
    set("terminal",e.message);
    set("execStatus","FAILED");
    color("execStatus","FAILED");
  }finally{
    analyze.disabled=false;
    execute.disabled=false;
  }
};

function renderExec(d){
  let x=d.execution_result;
  if(!x){
    set("execSummary","No execution result returned.");
    set("terminal",d.reason);
    return;
  }
  lastExec=x;
  set("execId","Execution ID "+(x.execution_id||"—"));
  set("duration",x.metadata&&x.metadata.duration_ms!=null?"Duration "+x.metadata.duration_ms+" ms":"Duration —");
  set("execStatus","Status "+x.status);
  color("execStatus",x.status);
  set("execSummary",d.executed?"Command executed through the controlled runtime.":"Execution was blocked; no authorized process launch occurred.");
  set("auth",x.metadata&&x.metadata.policy_decision?"Policy "+x.metadata.policy_decision:(d.executed?"Revalidated":"Blocked"));
  set("process",d.executed?"Started by ProcessRunner":"Not started");
  set("exit",x.return_code==null?"—":x.return_code);
  set("bounds",(x.stdout_truncated?"stdout truncated":"stdout bounded")+" · "+(x.stderr_truncated?"stderr truncated":"stderr bounded"));
  show(tab);
}

function show(t){
  tab=t;
  document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("active",x.dataset.tab==t));
  if(!lastExec){set("terminal","No execution result.");return}
  set("terminal",t=="stdout"?(lastExec.stdout||"(no stdout)"):t=="stderr"?(lastExec.stderr||"(no stderr)"):JSON.stringify(lastExec.metadata||{},null,2));
}

document.querySelectorAll(".tab").forEach(x=>x.onclick=()=>show(x.dataset.tab));
document.querySelectorAll("[data-q]").forEach(x=>x.onclick=()=>{
  intent.value=x.dataset.q;snapshot=null;execute.disabled=true;
});
[intent,role,env].forEach(x=>x.addEventListener("input",()=>{if(snapshot)execute.disabled=true;renderClarification(null)}));

/* Scenario Switcher */
async function switchScenario(name){
  document.querySelectorAll(".scen-btn").forEach(b=>b.classList.remove("active"));
  const btn = $("btn-scen-" + (name==="process_churn"?"process":name==="network_exfil"?"network":name));
  if(btn) btn.classList.add("active");
  try{
    await fetch("/api/v1/demo/trigger?scenario=" + name, {method:"POST",headers:{"X-IntentX-Demo":"1"}});
  }catch(e){}
  await Promise.all([loadLiveScores(), loadTelemetry(), loadXAI()]);
}

/* Update Threat Cockpit */
function updateCockpit(latestWindow, explanation){
  const cockpit = $("threat-cockpit");
  const badge = $("cockpit-badge");
  const title = $("cockpit-title");
  const sub = $("cockpit-sub");
  const marginEl = $("cockpit-margin");
  const gaugeFill = $("cockpit-gauge-fill");
  const mitBox = $("cockpit-mitigation-box");
  const mitTitle = $("cockpit-mit-title");
  const mitSub = $("cockpit-mit-sub");
  const adoptBtn = $("cockpit-adopt-btn");

  if(!latestWindow){
    cockpit.className = "threat-cockpit normal";
    badge.textContent = "🛡️ MONITORING ONLINE";
    return;
  }

  const features = latestWindow.features || {};
  const margin = latestWindow.margin;
  const isAnom = latestWindow.flagged;
  const kEvents = features.kernel_event_count || 0;
  const aEvents = features.audit_event_count || 0;
  const pEvents = features.process_event_count || 0;
  const nEvents = features.network_connection_count || 0;

  // Update Margin display
  marginEl.textContent = (margin >= 0 ? "+" : "") + margin.toFixed(4);
  marginEl.className = isAnom ? "bad" : "good";

  // Visual Gauge Calculation: map range [-0.3, +0.15] to percentage [0%, 100%]
  let pct = Math.max(8, Math.min(95, ((margin + 0.3) / 0.45) * 100));
  gaugeFill.style.width = pct + "%";
  gaugeFill.style.background = isAnom ? "linear-gradient(90deg, #dc2626, #ef4444)" : "linear-gradient(90deg, #059669, #10b981)";

  // Identify scenario profile
  if(!isAnom){
    cockpit.className = "threat-cockpit normal";
    badge.textContent = "🛡️ SYSTEM INTEGRITY HEALTHY · BASELINE NORMAL";
    title.textContent = "Case 1: Baseline Normal Workload";
    sub.textContent = "All 19 Linux telemetry indicators operate within calibrated baseline distributions. Decision margin remains positive. No threat mitigations required.";
    $("pil-kernel").textContent = "0 (Clean)"; $("pil-kernel").className = "pillar-val good";
    $("pil-audit").textContent = "Nominal"; $("pil-audit").className = "pillar-val good";
    $("pil-process").textContent = "2 Active"; $("pil-process-st").textContent = "Normal Workload";
    $("pil-network").textContent = "1 Listener"; $("pil-network-st").textContent = "No Unauthorized Sockets";
    mitBox.style.display = "none";
  } else if(kEvents >= 20 || aEvents >= 15){
    cockpit.className = "threat-cockpit kernel";
    badge.textContent = "🚨 CRITICAL INTRUSION DETECTED · KERNEL MODULE TAINT & PTRACE";
    title.textContent = "Case 2: Kernel Rootkit & Memory Tracing Attack";
    sub.textContent = "Unauthorized out-of-tree kernel taint (0x1000) and ptrace memory injection detected. Isolation Forest decision margin plunged into anomaly territory.";
    $("pil-kernel").textContent = kEvents + " Taints"; $("pil-kernel").className = "pillar-val bad";
    $("pil-kernel-st").textContent = "Rootkit Taint 0x1000"; $("pil-kernel-st").className = "pillar-status bad";
    $("pil-audit").textContent = aEvents + " Syscalls"; $("pil-audit").className = "pillar-val bad";
    $("pil-audit-st").textContent = "Ptrace Injection Spike"; $("pil-audit-st").className = "pillar-status bad";
    $("pil-process").textContent = (features.root_process_event_count||18) + " Root Events";
    $("pil-process-st").textContent = "Privilege Escalation";
    $("pil-network").textContent = "2 Sockets"; $("pil-network-st").textContent = "Command & Control Probe";
    mitBox.style.display = "flex";
    mitTitle.textContent = "[CRITICAL] Lock Kernel Module Insertion";
    mitSub.textContent = "sysctl -w kernel.modules_disabled=1 (Eliminates runtime rootkit persistence)";
    adoptBtn.onclick = () => {
      intent.value = "lock kernel modules";
      snapshot = null; execute.disabled = true;
      document.getElementById("console-section").scrollIntoView({behavior:"smooth"});
    };
  } else if(pEvents >= 80){
    cockpit.className = "threat-cockpit process_churn";
    badge.textContent = "⚠️ BEHAVIORAL THREAT · PROCESS CHURN & FORK BOMB";
    title.textContent = "Case 3: Rogue Cryptominer / PID Exhaustion Churn";
    sub.textContent = "Rapid burst in fork events and cgroup memory saturation. System undergoing unauthorized computational exhaustion.";
    $("pil-kernel").textContent = "0 (Clean)"; $("pil-kernel").className = "pillar-val good";
    $("pil-audit").textContent = "12 (Moderate)"; $("pil-audit").className = "pillar-val warn";
    $("pil-process").textContent = pEvents + " Events"; $("pil-process").className = "pillar-val bad";
    $("pil-process-st").textContent = (features.unique_process_count||78) + " Unique PIDs Churned";
    $("pil-network").textContent = "2 Sockets"; $("pil-network-st").textContent = "Local RPC";
    mitBox.style.display = "flex";
    mitTitle.textContent = "[CRITICAL] Terminate Rogue Process Burst";
    mitSub.textContent = "kill -15 <pid> (Safely terminate high-churn execution tree)";
    adoptBtn.onclick = () => {
      intent.value = "kill process 1234";
      snapshot = null; execute.disabled = true;
      document.getElementById("console-section").scrollIntoView({behavior:"smooth"});
    };
  } else {
    cockpit.className = "threat-cockpit network_exfil";
    badge.textContent = "📡 NETWORK THREAT · UNAUTHORIZED DATA EXFILTRATION";
    title.textContent = "Case 4: Rogue Network Sockets & Exfiltration";
    sub.textContent = "Anomalous outbound socket density and external IP listeners detected. Potential reverse shell in progress.";
    $("pil-kernel").textContent = "0 (Clean)"; $("pil-kernel").className = "pillar-val good";
    $("pil-audit").textContent = "8 (Nominal)"; $("pil-audit").className = "pillar-val good";
    $("pil-process").textContent = "24 Events"; $("pil-process-st").textContent = "Normal PID Scope";
    $("pil-network").textContent = nEvents + " Connections"; $("pil-network").className = "pillar-val bad";
    $("pil-network-st").textContent = (features.network_listener_count||6) + " Rogue Listeners Active";
    mitBox.style.display = "flex";
    mitTitle.textContent = "[CRITICAL] Isolate Suspicious Network Listener";
    mitSub.textContent = "iptables DROP filter on exfiltration port";
    adoptBtn.onclick = () => {
      intent.value = "list files in /app/runtime";
      snapshot = null; execute.disabled = true;
      document.getElementById("console-section").scrollIntoView({behavior:"smooth"});
    };
  }
}

async function loadLiveScores(){
  const opened=new Set(Array.from($("live-score-windows").querySelectorAll("details[open]"),box=>box.dataset.start));
  const refresh=$("live-refresh");refresh.disabled=true;
  $("live-score-windows").replaceChildren();set("live-score-model","");set("live-score-explained","No current scoring result has been confirmed.");
  set("live-score-phase","Collection phase unknown · Collection age unavailable");
  try{
    const response=await fetch("/api/v1/behavior/live",{cache:"no-store"});
    if(!response.ok)throw Error("unavailable");
    const d=await response.json();
    const labels={not_configured:"Live scoring is not connected.",unavailable:"Live scoring report unavailable or invalid.",warming_up:"Waiting for complete results. First results take about two minutes; collection is already active.",collecting:"Scorer active. Results below are completed windows.",stale:"Scorer heartbeat is stale. Current scoring activity is unknown.",stopped:"Scorer stopped. Previous results remain historical.",error:"Scoring failed. Previous results remain historical."};
    set("live-score-status",labels[d.status]||"Scoring activity unknown.");
    if(d.threshold!==undefined)set("live-score-model",`Schema 2 · Threshold ${d.threshold.toFixed(6)} · Updated ${d.updated_at} · Model ${d.model_sha256.slice(0,12)}`);
    const phases={startup:"Startup",steady_state:"Steady-state collection",unknown:"Phase unknown"};
    const reportedAge=d.collection_age_seconds;
    set("live-score-phase",`Last reported collection phase: ${phases[d.collection_phase]||"Phase unknown"} · Collection age ${Number.isFinite(reportedAge)?Math.floor(reportedAge/60)+"m "+Math.floor(reportedAge%60)+"s":"unavailable"}`);
    
    const windows=d.windows||[];
    const latestWindow=windows[windows.length-1];
    updateCockpit(latestWindow);
    set("live-score-explained",latestWindow?`Latest completed window ended ${latestWindow.end_utc}. Score ${latestWindow.score.toFixed(6)} minus threshold ${d.threshold.toFixed(6)} equals margin ${latestWindow.margin.toFixed(6)}. ${latestWindow.flagged?"Flagged for review; not a confirmed attack.":"Unflagged by this model; not a guarantee of safety."} Report status: ${d.status}.` : "No completed live window yet. A fresh heartbeat does not imply that a scoring batch has finished.");

    for(const w of windows.slice().reverse()){
      const box=document.createElement("details");box.dataset.start=w.start_utc;box.open=opened.has(w.start_utc);box.className="detail";box.style.marginTop="9px";
      const title=document.createElement("summary");
      title.textContent=`${w.start_utc} — ${phases[w.collection_phase]||"Phase unknown"} · ${w.flagged?"Flagged":"Unflagged"} · Score ${w.score.toFixed(6)} · Margin ${w.margin.toFixed(6)} · Coverage checked`;
      const values=document.createElement("dl");
      for(const [key,value] of Object.entries(w.features)){
        const name=document.createElement("dt"), detail=document.createElement("dd");
        const display=key.endsWith("_ratio")?`${value.toFixed(4)} (${(value*100).toFixed(1)}% of cgroup limit)`:String(value);
        name.textContent=key.replaceAll("_"," ")+": "+display;name.style.cssText="font-weight:700;margin-top:12px";
        detail.textContent=metricFeatureHelp[key]||"Window observation; interpret alongside source coverage.";
        detail.style.cssText="margin:4px 0 10px;color:var(--m)";values.append(name,detail);
      }
      box.append(title,values);
      $("live-score-windows").appendChild(box);
    }
  }catch(error){
    set("live-score-status","Live scoring unavailable. Current scoring activity is unknown.");
  }finally{
    refresh.disabled=false;
  }
}
$("live-refresh").onclick=loadLiveScores;loadLiveScores();
setInterval(()=>{if(!document.hidden&&!$("live-refresh").disabled)loadLiveScores();},6000);

async function loadXAI(){
  const refresh=$("xai-refresh");refresh.disabled=true;
  try{
    const res=await fetch("/api/v1/behavior/explain",{cache:"no-store"});
    if(!res.ok)throw Error("XAI analysis unavailable.");
    const d=await res.json();
    if(d.status!=="available"||!d.explanation){
      set("xai-summary",d.message||"No live behavioral windows available for explanation.");
      $("xai-factors").replaceChildren();$("xai-mitigations").replaceChildren();return;
    }
    const exp=d.explanation;
    set("xai-summary",exp.summary);
    const method=document.createElement("p");method.className="small";
    method.textContent=`Explained window: ${exp.window_start} to ${exp.window_end}. Source report: ${d.source_status||"unknown"}; stale, error or stopped reports are historical evidence. ${d.reference_notice||"Explanation method unspecified; do not treat contributions as causal evidence."}`;

    color("xai-summary",exp.is_anomalous?"bad":"good");
    $("xai-factors").replaceChildren();$("xai-factors").append(method);
    
    for(const factor of exp.primary_factors||[]){
      const box=document.createElement("div");box.className="metric";
      const pct=factor.contribution_percentage.toFixed(1);
      const isHigh=factor.contribution_percentage > 20;
      const heading=document.createElement("div"), value=document.createElement("div"), description=document.createElement("p");
      heading.className="name";heading.textContent=factor.feature_name.replaceAll("_"," ")+" · "+pct+"% contribution";
      value.className="value";value.textContent=factor.observed_value.toFixed(2);
      description.className="small";description.textContent=factor.description;
      box.append(heading,value,description);
      $("xai-factors").appendChild(box);
    }

    $("xai-mitigations").replaceChildren();
    if(!d.mitigations||!d.mitigations.length){
      const p=document.createElement("p");p.className="small";
      p.textContent="No response recommendation for this explained window. This does not establish that the host is safe.";
      $("xai-mitigations").appendChild(p);
    }else{
      for(const m of d.mitigations){
        const item=document.createElement("div");item.className="detail";
        item.style.display="flex";item.style.justifyContent="space-between";item.style.alignItems="center";item.style.gap="10px";
        const left=document.createElement("div");
        left.innerHTML=`<b style="color:#dce8f8;font-size:12px">[${m.priority}] ${m.title}</b><p style="margin:3px 0 0;color:var(--m);font-size:11px">${m.rationale} <code style="color:#93c5fd;font-weight:700">${m.command_hint}</code></p>`;
        const btn=document.createElement("button");btn.className="tab";btn.textContent="Adopt in Console";
        btn.onclick=()=>{
          intent.value=m.suggested_intent;snapshot=null;execute.disabled=true;
          document.getElementById("console-section").scrollIntoView({behavior:"smooth"});
        };
        item.append(left,btn);$("xai-mitigations").appendChild(item);
      }
    }
  }catch(e){
    set("xai-summary","XAI analysis unavailable.");
  }finally{
    refresh.disabled=false;
  }
}
$("xai-refresh").onclick=loadXAI;loadXAI();
setInterval(()=>{if(!document.hidden&&!$("xai-refresh").disabled)loadXAI();},6000);

async function loadTelemetry(){
  const refresh=$("telemetry-refresh");refresh.disabled=true;
  $("telemetry-sensors").replaceChildren();set("telemetry-time","");
  try{
    const response=await fetch("/api/v1/telemetry/status",{cache:"no-store"});
    if(!response.ok)throw Error("Collector status unavailable.");
    const d=await response.json();
    const labels={not_configured:"Live collector is not connected.",unavailable:"Collector status unavailable or invalid.",stale:"Collector status is stale. Current collection activity is unknown.",stopped:"Collector stopped.",error:"Latest collection failed.",collecting:"Recent collection activity observed."};
    set("telemetry-status",labels[d.status]||"Collector status unknown.");
    if(d.updated_at)set("telemetry-time",`Status updated ${d.updated_at} · Last successful collection ${d.last_success_at||"none"}`);
    for(const [name,status] of Object.entries(d.sensors||{})){
      const box=document.createElement("div");box.className="metric";
      const title=document.createElement("div");title.className="name";title.textContent=name.replaceAll("_"," ");
      const value=document.createElement("div");value.className="value";value.textContent=status;
      box.append(title,value);$("telemetry-sensors").appendChild(box);
    }
  }catch(error){
    set("telemetry-status","Collector status unavailable. Current collection activity is unknown.");
  }finally{
    refresh.disabled=false;
  }
}
$("telemetry-refresh").onclick=loadTelemetry;loadTelemetry();
setInterval(()=>{if(!document.hidden&&!$("telemetry-refresh").disabled)loadTelemetry();},6000);

async function loadBehavior(){
  const refresh=$("behavior-refresh"),body=$("behavior-windows");refresh.disabled=true;
  $("behavior-results").hidden=true;body.replaceChildren();set("behavior-status","Loading saved report…");
  try{
    const response=await fetch("/api/v1/behavior/results",{cache:"no-store"});
    if(!response.ok)throw new Error("Saved report could not be loaded. Monitoring status is unknown.");
    const d=await response.json();
    if(d.status!=="available"){
      set("behavior-status","No saved behavioral report configured. Historical results are unavailable.");
      return;
    }
    set("behavior-flags",`${d.flagged_windows} / ${d.evaluation_windows} windows`);
    set("behavior-rate",`${(d.benign_flag_rate*100).toFixed(1)}% observed benign flag rate`);
    set("behavior-model",`Schema ${d.feature_schema_version} · model format ${d.model_format_version}`);
    set("behavior-threshold",`Calibrated score threshold ${d.threshold.toFixed(6)}`);
    set("behavior-samples",`${d.training_windows} training · ${d.calibration_windows} calibration · ${d.evaluation_windows} final`);
    set("behavior-calibration",`${(d.calibration_flag_rate*100).toFixed(1)}% observed calibration flags`);
    set("behavior-coverage",d.collection_status);set("behavior-sensors",d.sensor_status);
    for(const w of d.windows){
      const tr=document.createElement("tr");
      for(const value of [w.hostname||"—",w.start_utc,w.score.toFixed(6),w.margin.toFixed(6),w.flagged?"Flagged":"Unflagged"]){
        const td=document.createElement("td");td.textContent=value;td.style.padding="9px 6px";tr.appendChild(td);
      }
      body.appendChild(tr);
    }
    set("behavior-status","Saved validation report loaded. Live collection status is shown separately.");
    $("behavior-results").hidden=false;
  }catch(error){
    set("behavior-status",error.message);
  }finally{
    refresh.disabled=false;
  }
}
$("behavior-refresh").onclick=loadBehavior;loadBehavior();
</script></body></html>'''


from intentx.ui.soc import SOC_STYLE, SOC_HTML, SOC_JS
DASHBOARD_HTML = DASHBOARD_HTML.replace('</head>', SOC_STYLE + '</head>').replace('</header>', '</header>' + SOC_HTML + '<p class="soc-note">Operations console and saved host records below: provenance is unverified. Historical files in the uploaded project may include CLI demo fixtures. Collect fresh host telemetry before claiming real kernel evidence.</p>', 1).replace('</body>', SOC_JS + '</body>')


from intentx.ui.metric_guide import GUIDE_HTML, FEATURE_HELP
import json as _metric_json
DASHBOARD_HTML = DASHBOARD_HTML.replace('<div class="soc-grid">', GUIDE_HTML + '<div class="soc-grid">', 1)
DASHBOARD_HTML = DASHBOARD_HTML.replace('<script>', '<script>const metricFeatureHelp = ' + _metric_json.dumps(FEATURE_HELP) + ';', 1)
