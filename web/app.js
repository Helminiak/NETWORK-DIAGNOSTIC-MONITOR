'use strict';
const $ = id => document.getElementById(id);
const text = (id, value) => { $(id).textContent = value == null || value === '' ? '—' : String(value); };
const tone = status => ['OK','DELTA','HEALTHY'].includes(status) ? 'good' : ['FAIL','CRITICAL','DNS_ANSWER_REDIRECTION','ANSWER_ANOMALY'].includes(status) ? 'bad' : 'unknown';
let current = null, receivedAt = 0, offline = true, historyMode = false;
const title = code => ({DNS_ANSWER_REDIRECTION:'Public DNS names are returning private addresses',DNS_INTEGRITY_WATCH:'A DNS answer needs investigation',UPSTREAM_WAN_CONFIRMED:'Correlated external-path failures',HEALTHY:'No corroborated fault in fresh observations',WAITING_FOR_EVIDENCE:'Waiting for fresh probe evidence',DNS_TCP_PATH_WATCH:'DNS over TCP is failing selectively',ICMP_ONLY_WATCH:'ICMP loss needs independent corroboration',PROVIDER_OR_HOST_WATCH:'An endpoint or sensor observation needs review'}[code] || String(code || 'Waiting for status').replaceAll('_',' '));
function setNode(id, status, label) { $(id+'-node').className='node '+tone(status); text(id+'-badge',label || status); }
function formatRate(value) { return Number.isFinite(value) ? value.toFixed(2) : '—'; }
function render(data) {
  if (!data.sensor || !data.network || !data.topology || !Array.isArray(data.probes)) return;
  const live = data.lifecycle === 'RUNNING' && !offline && !historyMode;
  const observed=live || historyMode;
  document.body.classList.toggle('offline',!observed);
  const code = data.network.code, active = data.network.activeIncident;
  const alertTone = active || data.network.severity === 'CRITICAL' ? 'bad' : code === 'HEALTHY' && live ? 'good' : 'unknown';
  $('incident').className='incident '+alertTone;
  text('incident-label',historyMode ? 'HISTORICAL LOG REPLAY · NOT LIVE' : !live ? 'SENSOR STATUS UNAVAILABLE · LAST SNAPSHOT' : active ? 'ACTIVE INCIDENT · SENSOR PATH' : 'CURRENT ASSESSMENT · SENSOR PATH');
  text('assessment-title',title(code)); text('assessment-text',data.network.text);
  let detail = data.network.answerAnomalyCount ? 'Nonpublic answers: '+(data.network.returnedAddresses || []).join(', ')+' · Source device unproven.' : '';
  if (data.network.unresolvedAtStop || (!live && active)) detail += ' Incident unresolved at the last sample. No recovery is inferred.';
  text('incident-detail',detail || (live ? 'Updated from fresh probe evidence.' : 'Displayed observations are historical; live health is unknown.'));
  text('sensor-context',data.sensor.name+' · '+data.sensor.adapter+' · '+data.sensor.role+' · Single-sensor measurements');
  text('updated',(historyMode ? 'Archive sample: ' : 'Snapshot: ')+new Date(data.generatedUtc).toLocaleString(undefined,{timeZoneName:'short'})+' · '+new Date(data.generatedUtc).toISOString().slice(11,19)+' UTC');
  text('sensor-name',data.sensor.name); text('sensor-adapter',data.sensor.adapter);
  setNode('sensor',live ? data.monitor.probes : 'STALE',live ? data.monitor.probes : historyMode ? 'Historical' : 'Unavailable');
  const gw=data.topology.nodes.find(n=>n.kind==='Gateway');
  const gwProbe=data.probes.filter(r=>r.scope==='Gateway' && r.protocol==='ICMP').sort((a,b)=>a.ageMs-b.ageMs)[0];
  const gwState=observed && gw ? gw.status : 'STALE';
  text('gateway-name',gw ? gw.label : 'Gateway'); text('gateway-address',data.sensor.gateway); setNode('gateway',gwState,observed && gw ? gw.status+' · ICMP only' : 'Last observations');
  text('gateway-status',observed && gw ? gw.status+(historyMode ? ' (archive)' : '') : historyMode ? 'Historical' : 'Unknown');
  text('gateway-detail',gwProbe && gwProbe.status==='OK' ? gwProbe.latencyMs+' ms · ICMP only' : 'No fresh successful ICMP sample');
  const publicTcp=data.probes.filter(r=>r.protocol==='TCP443' && r.resolutionMode==='PINNED_IP' && r.publicDestination===true && r.status!=='STALE');
  const goodControls=publicTcp.filter(r=>r.status==='OK').length;
  const upState=live && code==='UPSTREAM_WAN_CONFIRMED' ? 'FAIL' : live && goodControls>=2 ? 'OK' : 'UNDETERMINED';
  setNode('upstream',upState,upState==='FAIL' ? 'Path failure' : upState==='OK' ? 'Public TCP reachable' : 'Ownership undetermined');
  text('upstream-detail',publicTcp.length ? goodControls+' / '+publicTcp.length+' pinned TCP controls pass' : 'Pinned controls not measured in this snapshot');
  text('dns-status',observed ? data.network.answerAnomalyCount ? 'Answer anomaly' : data.probes.some(r=>r.protocol==='DNS_UDP' && r.status==='OK') ? 'Wire replies' : 'Unknown' : 'Last observations');
  text('dns-detail',data.network.answerAnomalyCount ? data.network.answerAnomalyCount+' fresh answer observations flagged' : 'Public-address policy is not DNSSEC verification');
  text('traffic-status',observed ? formatRate(data.traffic.rxMbps)+' / '+formatRate(data.traffic.txMbps) : '— / —');
  text('traffic-detail',data.traffic.counterState==='RESET_OR_INTERFACE_CHANGE' ? 'Counter reset · next sample creates a baseline' : data.traffic.counterState==='SAMPLING_GAP' ? 'Sampling gap · current rate unknown' : 'Mbps · sensor interface only');
  text('probe-status',live ? data.monitor.probes : historyMode ? 'Historical' : 'Unavailable');
  text('probe-detail',(data.monitor.gapCount == null ? 'Unknown' : data.monitor.gapCount)+' coordinator gaps · '+(data.monitor.storageDropped == null ? 'Unknown' : data.monitor.storageDropped)+' suppressed writes');
  text('link-speed',data.sensor.linkSpeed ? data.sensor.linkSpeed+' · PHY rate' : 'Link rate unavailable'); text('visibility-interface',data.sensor.adapter);
  const resources=data.monitor.resources;
  const measured=observed && resources && ['OK','PARTIAL'].includes(resources.status);
  text('monitor-memory',measured && Number.isFinite(resources.workingSetBytes) ? (resources.workingSetBytes/1048576).toFixed(1)+' MiB · process resident RAM' : 'Unmeasured or stale');
  text('monitor-cpu',measured && Number.isFinite(resources.cpuPercentOneCore) ? resources.cpuPercentOneCore.toFixed(1)+'% · 100% = one logical CPU' : 'Unmeasured or stale');
  text('visibility-lan',data.topology.nodes.filter(n=>n.kind==='LAN').length+' configured targets');
  text('footer-state',data.programVersion+' · '+data.lifecycle+' · '+(live ? 'Read-only' : 'Live state unknown'));
  const extra=$('extra-nodes'); extra.replaceChildren();
  for (const n of data.topology.nodes.filter(n=>['LAN','Gateway2'].includes(n.kind))) { const card=document.createElement('article');card.className='node '+(live ? tone(n.status) : 'unknown');const h=document.createElement('h3'),p=document.createElement('p'),s=document.createElement('span');h.textContent=n.label;p.textContent=n.address;s.className='node-state';s.textContent=live ? n.status+' · ICMP' : 'Last observations';card.append(h,p,s);extra.append(card); }
  renderRows(); renderTraffic(data.traffic.history || []);
  const events=$('events');events.replaceChildren();for(const event of data.recentEvents || []){const li=document.createElement('li');li.textContent=event;events.append(li);} if(!events.children.length){const li=document.createElement('li');li.textContent='No recent events';events.append(li);}
  $('export').disabled=false;
}
function renderRows() {
  if(!current || !current.probes) return;
  const filter=$('filter').value;
  let rows=current.probes.filter(r=>['ICMP','DNS_UDP','DNS_TCP','DOH_ENDPOINT','TCP443','HTTPS','TRACE'].includes(r.protocol));
  rows=rows.filter(r=>filter==='ALL' || filter==='DNS' && ['DNS_UDP','DNS_TCP','DOH_ENDPOINT'].includes(r.protocol) || filter==='ISSUES' && (r.status==='FAIL' || r.status==='STALE' || r.answerPolicy==='PUBLIC_NAME_NONPUBLIC_ANSWER') || r.protocol===filter);
  const rank=r=>r.status==='STALE' ? 3 : r.answerPolicy==='PUBLIC_NAME_NONPUBLIC_ANSWER' ? 0 : r.status==='FAIL' ? 1 : 2;
  rows.sort((a,b)=>rank(a)-rank(b)||a.protocol.localeCompare(b.protocol)||a.name.localeCompare(b.name)||a.ageMs-b.ageMs);
  const body=$('probe-rows');body.replaceChildren();
  for (const r of rows) {
    const tr=document.createElement('tr');const anomaly=r.answerPolicy==='PUBLIC_NAME_NONPUBLIC_ANSWER' || r.stage==='DNS_ANSWER_NONPUBLIC';if(anomaly) tr.className='anomaly';
    const interpretation=anomaly ? 'Nonpublic answer · '+(r.addresses && r.addresses.length ? r.addresses : [r.ip]).join(', ') : r.resolutionMode==='PINNED_IP' ? 'Pinned IP · bypasses DNS' : r.protocol==='DOH_ENDPOINT' ? 'Endpoint reachability only' : r.protocol==='HTTPS' && r.measurement==='HEAD_HEADERS_ONLY' ? r.stage+' · HEAD headers only' : r.protocol==='TRACE' ? r.stage+' · '+(r.signature || 'no hops') : r.answerPolicy==='PUBLIC_ADDRESS_ONLY' ? 'Public IPv4 answer · '+(r.addresses || []).join(', ') : r.answerPolicy==='EXEMPT' ? 'Answer-policy exemption · '+r.stage : r.stage;
    const values=[r.name,r.queryName || r.ip || '—',r.wireStatus,interpretation,Number.isFinite(r.latencyMs) ? r.latencyMs.toFixed(1)+' ms' : '—',(r.ageMs/1000).toFixed(1)+' s'];
    values.forEach((value,i)=>{const td=document.createElement('td');td.textContent=value || '—';if(i===0){const small=document.createElement('small');small.textContent=r.protocol+' · '+r.provider;td.append(small);}if(i===2){td.className='status-'+tone((!offline || historyMode) && r.status!=='STALE' ? r.status : 'STALE');const small=document.createElement('small');small.textContent=historyMode ? 'historical' : offline ? 'last snapshot' : r.status==='STALE' ? 'stale' : r.stage;td.append(small);}if(i===3 && anomaly) td.className='status-bad';tr.append(td);});body.append(tr);
  }
  if(current.probeRowsOmitted){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=6;td.textContent=current.probeRowsOmitted+' older rows omitted from this bounded status response; raw incident evidence remains available.';tr.append(td);body.append(tr);}
  if(!rows.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=6;td.textContent='No observations for this filter.';tr.append(td);body.append(tr);}
}
function renderTraffic(samples) {
  const host=$('traffic-chart');host.replaceChildren();
  const usable=samples.filter(s=>Number.isFinite(s.rxMbps)||Number.isFinite(s.txMbps));
  if(!usable.length){const p=document.createElement('p');p.className='muted';p.textContent='Waiting for two comparable counter samples.';host.append(p);return;}
  const ns='http://www.w3.org/2000/svg',svg=document.createElementNS(ns,'svg');svg.setAttribute('viewBox','0 0 600 145');svg.setAttribute('role','img');svg.setAttribute('aria-label','Sensor interface throughput: receive in green, send in blue');
  const max=Math.max(.1,...usable.map(s=>Math.max(s.rxMbps || 0,s.txMbps || 0)));const start=samples[0].monoMs,end=Math.max(start+1,samples[samples.length-1].monoMs);
  const guide=document.createElementNS(ns,'path');guide.setAttribute('d','M40 25 H588 M40 75 H588 M40 125 H588');guide.setAttribute('stroke','#293648');svg.append(guide);
  for(const [key,color] of [['rxMbps','#6ad5b2'],['txMbps','#87bcff']]){let d='',previous=false;for(const s of samples){if(!Number.isFinite(s[key])){previous=false;continue;}const x=40+548*(s.monoMs-start)/(end-start),y=125-100*s[key]/max;d+=(previous?' L':' M')+x.toFixed(1)+' '+y.toFixed(1);previous=true;}const path=document.createElementNS(ns,'path');path.setAttribute('d',d);path.setAttribute('fill','none');path.setAttribute('stroke',color);path.setAttribute('stroke-width','2');svg.append(path);}
  for(const [x,y,value] of [[0,29,max.toFixed(1)],[0,129,'0'],[40,143,'Receive / Send · Mbps'],[435,143,'Last '+Math.round((end-start)/1000)+' s']]){const t=document.createElementNS(ns,'text');t.setAttribute('x',x);t.setAttribute('y',y);t.textContent=value;svg.append(t);}host.append(svg);
}
function connection(label,kind){text('connection',label);$('connection').className='badge '+kind;}
async function poll() {
  const controller=new AbortController(),deadline=setTimeout(()=>controller.abort(),1800);
  try {
    const response=await fetch('/api/status',{cache:'no-store',signal:controller.signal});if(!response.ok) throw new Error('Status HTTP '+response.status);
    const data=await response.json();if(data.schemaVersion!==1 || !data.sensor || !data.monitor || !data.traffic || !data.topology || !Array.isArray(data.probes)) throw new Error('Awaiting complete status');
    current=data;receivedAt=performance.now();historyMode=data.lifecycle==='HISTORICAL';offline=data.snapshotAgeMs>10000 || data.lifecycle!=='RUNNING';
    connection(historyMode ? 'Historical replay' : offline ? 'Stale / stopped' : 'Live · local',historyMode || offline ? 'unknown':'good');render(current);
  } catch(error){offline=true;connection('Unavailable · retrying','unknown');if(current) render(current);}
  finally{clearTimeout(deadline);setTimeout(poll,2000);}
}
$('filter').addEventListener('change',renderRows);
$('fullscreen').addEventListener('click',async()=>{try{if(document.fullscreenElement) await document.exitFullscreen();else await document.documentElement.requestFullscreen();}catch{connection('Full screen unavailable','unknown');}});
$('export').addEventListener('click',()=>{if(!current) return;const blob=new Blob([JSON.stringify(current,null,2)],{type:'application/json'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='network-status-'+current.sensor.name.replace(/[^A-Za-z0-9_.-]/g,'_')+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
setInterval(()=>{if(!offline && current && performance.now()-receivedAt+current.snapshotAgeMs>10000){offline=true;connection('Stale · awaiting samples','unknown');render(current);}},1000);
poll();
