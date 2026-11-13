try {
  const theme = localStorage.getItem('ras-log-analyser.theme');
  if (['dark','light','parallels'].includes(theme)) document.documentElement.dataset.theme = theme;
} catch { /* Default theme */ }
const metrics = [
  ['sessions','Browser sessions'], ['upload_sessions','Sessions with uploads'],
  ['files','Individual logs uploaded'], ['bundles','Bundles uploaded'],
  ['uploaded_bytes','MB uploaded'], ['processed_bytes','MB processed'], ['logs','Logs analysed']
];
async function refresh(){
  const status = document.getElementById('usage-status');
  const button = document.getElementById('refresh');
  button.disabled = true;
  try {
    const response = await fetch('/api/usage');
    if (!response.ok) throw new Error();
    const totals = await response.json();
    document.getElementById('usage-cards').replaceChildren(...metrics.map(([key,label])=>{
      const card=document.createElement('article'), title=document.createElement('span'), number=document.createElement('strong');
      title.textContent=label;
      number.textContent=key.endsWith('_bytes') ? (totals[key]/1000000).toLocaleString(undefined,{maximumFractionDigits:3}) : totals[key].toLocaleString();
      card.append(title,number);
      return card;
    }));
    status.textContent='Updated '+new Date().toLocaleTimeString();
  } catch { status.textContent='Could not load usage totals. Please try again.'; }
  finally { button.disabled=false; }
}
document.getElementById('refresh').addEventListener('click',refresh);
refresh();
