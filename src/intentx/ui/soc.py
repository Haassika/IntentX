"""SOC presentation layer; existing operations console remains below."""
SOC_STYLE = '''
<style>
body{background:#0b1220}main{max-width:1420px}.soc{margin-bottom:30px}.soc-label{color:#8da7c9;font-size:11px;letter-spacing:.15em;text-transform:uppercase}.soc h2{font-size:28px;margin:10px 0}.soc p{color:#9fb1ca;line-height:1.6}.soc-grid{display:grid;grid-template-columns:1.2fr 1fr;gap:16px}.soc-card{background:#111d30;border:1px solid #293a54;border-radius:12px;padding:22px}.soc-wide{grid-column:1/-1}.soc-metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:18px 0}.soc-metric{padding:14px;background:#0b1525;border-radius:8px}.soc-metric b{display:block;font-size:24px;margin-top:8px;font-variant-numeric:tabular-nums}.soc button{padding:11px 16px;border:1px solid #425b7d;background:#203858;color:#edf4ff;border-radius:7px;cursor:pointer;margin:4px}.soc button:disabled{opacity:.5;cursor:wait}.soc button[aria-pressed=true]{background:#245ac2;border-color:#92b5ff}.soc button:focus-visible{outline:3px solid #9dd5ff}.soc-track{height:24px;background:#273951;position:relative;margin:18px 0 6px;border-radius:4px}.soc-threshold{position:absolute;height:34px;top:-5px;border-left:2px dashed #ffd27b}.soc-point{position:absolute;top:3px;width:18px;height:18px;border-radius:50%;background:#7bb7ff;transform:translateX(-50%)}.soc-evidence{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}.soc-evidence div{background:#0b1525;padding:14px;border-radius:6px}.soc-evidence b{display:block;font-size:24px;margin:8px 0}.soc small{color:#a6b9d2}.soc li{line-height:1.6;margin-bottom:12px}.soc table{width:100%;border-collapse:collapse}.soc td,.soc th{text-align:left;padding:10px;border-bottom:1px solid #293a54}.soc-alert{color:#ffb5b5}.soc-ok{color:#7ae2be}.scenario-bar,#threat-cockpit{display:none!important}.threat-cockpit{animation:none!important;box-shadow:none!important}.soc-note{border-left:3px solid #d7b56d;padding-left:14px}@media(max-width:850px){.soc-grid{grid-template-columns:1fr}.soc-metrics,.soc-evidence{grid-template-columns:repeat(2,1fr)}}
</style>'''
SOC_HTML = '''
<section class="soc" aria-label="Security operations center">
<div class="soc-label">IntentX / Security operations center</div>
<h2>Explain the signal. Guide the response.</h2>
<p>A controlled presentation workspace with an independent view of host sensor availability.</p>
<div class="soc-grid">
<section class="soc-card soc-wide"><div class="soc-label">System status · controlled evidence</div>
<h2 id="soc-status" aria-live="polite">Awaiting scenario</h2><p id="soc-summary">Select a predefined scenario to begin. No host intrusion is performed.</p>
<div class="soc-metrics"><div class="soc-metric">Anomaly score<b id="soc-score">—</b><small>Lower means more anomalous; not a probability.</small></div><div class="soc-metric">Threshold<b id="soc-limit">—</b><small>Fixed decision boundary for this demo.</small></div><div class="soc-metric">Decision margin<b id="soc-margin">—</b><small>Score minus threshold; negative is flagged.</small></div><div class="soc-metric">Assessment<b id="soc-severity">No data</b><small>Review asks for investigation, not a verdict.</small></div></div>
<div class="soc-track" role="img" aria-label="Anomaly score compared with threshold, scale minus one to zero"><span class="soc-threshold" style="left:43.835%"></span><span id="soc-point" class="soc-point" hidden></span></div>
<p id="soc-decision-explanation">Select a scenario to see the score calculation.</p>
<small>−1 ← more anomalous · dashed line = threshold · less anomalous → 0. A score below threshold flags a window; this is not a probability or proof of compromise.</small>
</section>
<section class="soc-card soc-wide"><div class="soc-label">Controlled demo controller</div>
<p class="soc-note">SIMULATED EVIDENCE · Scores are fixed presentation fixtures. Explanations use illustrative deviation attribution, not model inference. Kernel-security events here are synthetic.</p>
<div id="soc-controls"><button data-scenario="baseline">Normal baseline</button><button data-scenario="process_churn">Process anomaly</button><button data-scenario="network_exfil">Network anomaly</button><button data-scenario="kernel">Kernel security</button><button data-scenario="reset">Reset demo</button></div>
<p id="soc-connection" role="status">Connecting…</p></section>
<section class="soc-card soc-wide"><div class="soc-label">Live evidence cards · selected simulation</div><div id="soc-evidence" class="soc-evidence"><p>No scenario evidence.</p></div></section>
<section class="soc-card"><div class="soc-label">XAI explanation</div><p id="soc-xai">Awaiting evidence.</p><ol id="soc-factors"></ol></section>
<section class="soc-card"><div class="soc-label">Recommendations / response</div><p>Advisory only. Review suggested intents in the existing operations console below. Its validation, policy/RBAC and execution controls remain authoritative.</p><ol id="soc-response"></ol></section>
<section class="soc-card"><div class="soc-label">Host telemetry · separate sensor evidence</div><h2 id="soc-sensor-state">Checking availability</h2><p id="soc-sensor-detail">No real kernel evidence has been verified by this presentation.</p><small>Live telemetry status reports availability only. No anomaly scoring is performed by this status monitor. Availability comes from the existing telemetry status endpoint. Simulated scenarios never update these files. Inspect source provenance and freshness before making a host claim.</small></section>
<section class="soc-card"><div class="soc-label">Scenario timeline / status</div><p>Completed means the synthetic fixture is ready. State is shared within this server process, capped at 30 entries, and clears on restart.</p><ol id="soc-timeline"></ol></section>
</div></section>
'''
SOC_JS = r'''
<script>
(()=>{
 const el=id=>document.getElementById(id), put=(id,value)=>el(id).textContent=value;
 let busy=false, polling=false, lastGood=null;
 const fmt=v=>Number.isFinite(v)?v.toFixed(4):'—';
 function item(parent,text){const li=document.createElement('li');li.textContent=text;parent.append(li);}
 async function read(url,options={}){const r=await fetch(url,{cache:'no-store',signal:AbortSignal.timeout(8000),...options});if(!r.ok)throw Error('Request failed ('+r.status+')');return r.json();}
 function render(d){
  const w=d.windows?.at(-1), alert=!!w?.flagged;
  put('soc-status',w?(alert?'Alert · simulated anomaly':'Normal · simulated baseline'):'Awaiting scenario');
  el('soc-status').className=w?(alert?'soc-alert':'soc-ok'):'';
  put('soc-summary',w?'Selected scenario: '+d.scenario+' · '+d.status+' · synthetic evidence only':'Select a predefined scenario. Reset clears only the presentation state.');
  put('soc-score',fmt(w?.score));put('soc-limit',fmt(d.threshold));put('soc-margin',fmt(w?.margin));put('soc-severity',w?(alert?'Review':'Normal'):'No data');
  put('soc-decision-explanation',w?'Synthetic decision: '+w.score.toFixed(6)+' minus ('+d.threshold.toFixed(6)+') = '+w.margin.toFixed(6)+'. '+(alert?'The negative margin crosses the demo threshold.':'The non-negative margin does not cross the demo threshold.'):'No synthetic window selected; this does not mean the host is healthy.');
  el('soc-point').hidden=!w;if(w)el('soc-point').style.left=Math.max(0,Math.min(100,(w.score+1)*100))+'%';
  document.querySelectorAll('[data-scenario]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.scenario===d.scenario)));
  const evidence=el('soc-evidence');evidence.replaceChildren();
  const fields=['process_event_count','unique_process_count','network_connection_count','network_listener_count','kernel_event_count','audit_event_count'];
  for(const key of fields){const card=document.createElement('div'),label=document.createElement('small'),value=document.createElement('b'),source=document.createElement('small');label.textContent=key.replaceAll('_',' ');value.textContent=w?.features?.[key]??'—';source.textContent='Source: controlled simulation. '+(metricFeatureHelp[key]||'');card.append(label,value,source);evidence.append(card);}
  put('soc-xai',d.explanation?.summary||'Awaiting evidence.');
  const factors=el('soc-factors');factors.replaceChildren();for(const f of d.explanation?.primary_factors||[])item(factors,f.feature_name.replaceAll('_',' ')+': '+f.observed_value+' · '+f.contribution_percentage+'% illustrative contribution');
  const response=el('soc-response');response.replaceChildren();for(const m of d.mitigations||[]){item(response,m.priority+' · '+m.title+' — '+m.rationale);const adopt=document.createElement('button');adopt.textContent='Review intent: '+m.suggested_intent;adopt.addEventListener('click',()=>{const input=el('intent-text');input.value=m.suggested_intent;input.dispatchEvent(new Event('input',{bubbles:true}));el('execute').disabled=true;input.scrollIntoView({behavior:'smooth',block:'center'});input.focus();});response.lastChild.append(adopt);}if(!d.mitigations?.length)item(response,'No response recommended for the current presentation state.');
  const timeline=el('soc-timeline');timeline.replaceChildren();for(const t of [...d.timeline].reverse())item(timeline,new Date(t.at).toLocaleTimeString()+' · '+t.scenario+' · '+t.status);
 }
 async function refresh(){if(polling||busy)return;polling=true;try{render(await read('/api/v1/demo/status'));lastGood=new Date();put('soc-connection','Connected · refreshed '+lastGood.toLocaleTimeString()+' · polling every 2 seconds');}catch(e){put('soc-connection','Disconnected · displayed evidence may be stale. '+e.message);}finally{polling=false;}
 try{const t=await read('/api/v1/telemetry/status');put('soc-sensor-state',(t.status||'unknown').replaceAll('_',' '));put('soc-sensor-detail','Latest record: '+(t.updated_at||'unavailable')+' · '+Object.entries(t.sensors||{}).map(([name,status])=>name.replaceAll('_',' ')+': '+status).join(' · '));}catch(e){put('soc-sensor-state','Unavailable');put('soc-sensor-detail','Host sensor status could not be read. No kernel monitoring claim is made.');}}
 el('soc-controls').addEventListener('click',async e=>{const b=e.target.closest('[data-scenario]');if(!b||busy)return;busy=true;document.querySelectorAll('[data-scenario]').forEach(x=>x.disabled=true);put('soc-connection','Preparing '+b.dataset.scenario+'…');try{render(await read('/api/v1/demo/trigger?scenario='+encodeURIComponent(b.dataset.scenario),{method:'POST',headers:{'X-IntentX-Demo':'1'}}));put('soc-connection','Scenario completed · synthetic evidence ready');}catch(err){put('soc-connection',err.message+' · scenario change was not confirmed');}finally{busy=false;document.querySelectorAll('[data-scenario]').forEach(x=>x.disabled=false);}});
 refresh();setInterval(()=>{if(!document.hidden)refresh();},2000);
})();
</script>'''
