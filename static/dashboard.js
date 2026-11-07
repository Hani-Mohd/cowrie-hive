const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const COLS=[['ip','IP address'],['sess','Sessions'],['fail','Failed logins'],['ok','Successful logins'],['cmds','Commands'],['first','First seen'],['last','Last seen']];
let D=null,sk='sess',sd=-1;
async function refresh(){
  try{const r=await fetch('/api/data');
    if(r.status===401){location.href='/login';return}
    D=await r.json();render()}
  catch(e){$('#meta').textContent='Could not reach the dashboard server.'}
}
function render(){
  const sum=k=>D.ips.reduce((a,r)=>a+r[k],0);
  $('#meta').textContent=`${D.files} log files, ${D.n.toLocaleString()} events`+(D.bad?`, ${D.bad} unreadable lines skipped`:'')+`. Updated ${D.updated}, refreshes every 30 seconds. Times are UTC.`;
  $('#stats').innerHTML=[['Unique IPs',D.ips.length],['Sessions',sum('sess')],['Failed logins',sum('fail')],['Successful logins',sum('ok')],['Commands run',sum('cmds')]]
    .map(([l,v])=>`<div class="stat"><b>${v.toLocaleString()}</b><span>${l}</span></div>`).join('');
  bars('#users',D.users);bars('#pw',D.pw);bars('#topcmds',D.cmds,220);chart();geo();table();feed();
}
function bars(sel,a,w=118){
  const max=a.length?a[0][1]:1;
  $(sel).innerHTML=a.map(([k,v])=>`<div class="bar"><em class="mono" style="flex-basis:${w}px" title="${esc(k)}">${esc(k||'(empty)')}</em><i style="width:${Math.max(2,v/max*90)}px"></i><span>${v.toLocaleString()}</span></div>`).join('')||'<p class="note">Nothing yet.</p>';
}
function chart(){
  const d=D.days;
  if(!d.length){$('#chart').innerHTML='<p class="note">No connection events yet.</p>';return}
  const max=Math.max(...d.map(x=>x[1])),bw=56,H=150,W=d.length*bw+20;
  const s=d.map(([day,v],i)=>{const h=v/max*(H-34),x=10+i*bw;
    return `<rect x="${x+6}" y="${H-20-h}" width="${bw-12}" height="${h}" rx="2" fill="var(--acc)"/><text x="${x+bw/2}" y="${H-24-h}" text-anchor="middle" font-size="11" fill="var(--ink)">${v.toLocaleString()}</text><text x="${x+bw/2}" y="${H-5}" text-anchor="middle" font-size="10" fill="var(--mute)">${day.slice(5)}</text>`}).join('');
  $('#chart').innerHTML=`<svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="Connections per day">${s}</svg>`;
}
const NAMES={};
const mapReady=fetch('/static/world.svg')
  .then(r=>{if(!r.ok)throw new Error('map');return r.text()})
  .then(t=>{$('#map').innerHTML=t;document.querySelectorAll('#map path').forEach(p=>{NAMES[p.id]=p.dataset.name||p.id})})
  .catch(()=>{$('#map').innerHTML='<p class="note">Could not load the world map file.</p>'});
const mix=(a,b,t)=>a.map((v,i)=>Math.round(v+(b[i]-v)*t));
async function geo(){
  await mapReady;
  const paths=document.querySelectorAll('#map path');
  if(!paths.length)return;
  paths.forEach(p=>{p.style.fill='';const t=p.querySelector('title');if(t)t.remove()});
  const g=D.geo||[],known=g.filter(x=>x[0]!=='??'&&/^[A-Z]{2}$/.test(x[0]));
  const unknown=g.filter(x=>x[0]==='??').reduce((a,x)=>a+x[1],0);
  const max=known.length?known[0][1]:1;
  known.forEach(([cc,s,n])=>{
    const p=$('#map path[id="'+cc+'"]');
    if(!p)return;
    const t=Math.log(1+s)/Math.log(1+max);
    p.style.fill='rgb('+mix([255,211,107],[255,77,31],t).join(',')+')';
    const ti=document.createElementNS('http://www.w3.org/2000/svg','title');
    ti.textContent=(NAMES[cc]||cc)+': '+s.toLocaleString()+' sessions from '+n.toLocaleString()+' IPs';
    p.appendChild(ti);
  });
  bars('#geolist',known.slice(0,10).map(([cc,s])=>[NAMES[cc]||cc,s]),150);
  $('#geonote').textContent=D.geo_ok===false
    ?'GeoIP database not found, so no countries can be shown yet. See the setup steps.'
    :`${known.length} countries seen. ${unknown.toLocaleString()} sessions came from IPs with no country data. Hover a country for details. Colors use a log scale.`;
}
function filtered(){
  const q=$('#q').value.trim();
  return D.ips.filter(r=>!q||r.ip.includes(q)).sort((a,b)=>(a[sk]<b[sk]?-1:a[sk]>b[sk]?1:0)*sd);
}
function table(){
  $('#thead').innerHTML='<tr>'+COLS.map(([k,l])=>`<th tabindex="0" data-k="${k}">${l}${k===sk?(sd<0?' ▼':' ▲'):''}</th>`).join('')+'</tr>';
  const rows=filtered(),shown=rows.slice(0,300);
  $('#tbody').innerHTML=shown.map(r=>`<tr><td class="ip">${esc(r.ip)}</td><td>${r.sess}</td><td>${r.fail}</td><td class="${r.ok?'ok':''}">${r.ok}</td><td>${r.cmds}</td><td>${esc(r.first.slice(0,16).replace('T',' '))}</td><td>${esc(r.last.slice(0,16).replace('T',' '))}</td></tr>`).join('');
  $('#tnote').textContent=`Showing ${shown.length.toLocaleString()} of ${rows.length.toLocaleString()} IPs. Click a column to sort.`;
}
function feed(){
  const q=$('#q').value.trim();
  const ev=D.events.filter(e=>!q||e[1].includes(q));
  $('#feed').innerHTML=ev.map(([t,ip,k,x])=>`<tr><td>${esc(t.slice(0,19).replace('T',' '))}</td><td class="mono">${esc(ip)}</td><td>${k==='cmd'?'command':'download'}</td><td>${esc(x)}</td></tr>`).join('')||'<tr><td colspan="4">None yet.</td></tr>';
  $('#fnote').textContent=`Newest ${ev.length} events. The IP filter above also applies here. Click an IP in the table to filter by it.`;
}
$('#tbody').addEventListener('click',e=>{if(e.target.classList.contains('ip')){$('#q').value=e.target.textContent;table();feed()}});
$('#thead').addEventListener('click',e=>{const k=e.target.dataset.k;if(!k)return;sd=(k===sk)?-sd:-1;sk=k;table()});
$('#thead').addEventListener('keydown',e=>{if(e.key==='Enter'&&e.target.dataset.k)e.target.click()});
$('#q').addEventListener('input',()=>{if(D){table();feed()}});
$('#copy').addEventListener('click',async()=>{
  try{await navigator.clipboard.writeText(filtered().map(r=>r.ip).join('\n'));$('#copy').textContent='Copied'}catch{$('#copy').textContent='Copy blocked'}
  setTimeout(()=>$('#copy').textContent='Copy IP list',1500);
});
refresh();setInterval(refresh,30000);
