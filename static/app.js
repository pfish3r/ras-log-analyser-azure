function initializeThemePicker() {
  const picker = document.getElementById('theme-picker');
  const key = 'ras-log-analyser.theme';
  const themes = new Set(['dark', 'light', 'parallels']);
  let choice = 'parallels';
  try {
    const saved = localStorage.getItem(key);
    if (themes.has(saved)) choice = saved;
  } catch { /* The selector still works when browser storage is restricted. */ }
  picker.value = choice;
  document.documentElement.dataset.theme = choice;
  picker.addEventListener('change', () => {
    document.documentElement.dataset.theme = picker.value;
    try { localStorage.setItem(key, picker.value); } catch { /* Session only. */ }
  });
}
initializeThemePicker();

async function countSession(upload = false){
  // The browser retains only a boolean flag; no visitor identifier is sent.
  const key = upload ? 'ras.usage.upload' : 'ras.usage.visit';
  try {
    if (sessionStorage.getItem(key)) return;
    sessionStorage.setItem(key, '1');
    const response = await fetch('/api/usage/session', {method:'POST',
      headers:{'X-Logwatch-Analyze':'1', 'X-Usage-Event':upload?'upload':'visit'}});
    if (!response.ok) sessionStorage.removeItem(key);
  } catch { /* Statistics are optional when browser storage is unavailable. */ }
}
countSession();

let knownIssues=[];
const $ = id => document.getElementById(id);
let analysisData = null, selectedAnalysisIssue = null;
const labels = {login:'Login',login_failed:'Login failed',connection:'Connection',logout:'Logout',error:'Error',warning:'Warning',info:'Info'};
const el = (tag, text, cls) => {const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node;};
async function copyLogMessage(text,button){
  let copied=false;
  try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);copied=true;}}catch(error){}
  if(!copied){
    const helper=el('textarea');helper.className='clipboard-helper';helper.value=text;helper.setAttribute('readonly','');document.body.append(helper);helper.select();
    try{copied=document.execCommand('copy');}catch(error){}finally{helper.remove();}
  }
  const original=button.textContent;button.textContent=copied?'Copied':'Copy failed';
  setTimeout(()=>button.textContent=original,1500);
}
function errorActions(event){
  const actions=el('div',undefined,'error-actions');
  const copy=el('button','Copy message');copy.type='button';copy.addEventListener('click',()=>copyLogMessage(event.raw,copy));
  const search=el('button','Search Google AI ↗');search.type='button';search.title='Opens Google and sends this log message as the search query';
  search.addEventListener('click',()=>{
    const issueType=event.kind==='warning'?'warning':event.kind==='error'?'error':'entry';
    const prompt=`Explain this Parallels RAS log ${issueType} and suggest likely causes and fixes:\n\n${event.raw.slice(0,1500)}`;
    window.open(`https://www.google.com/search?udm=50&q=${encodeURIComponent(prompt)}`,'_blank','noopener,noreferrer');
  });
  const save=el('button','Save as known issue');save.type='button';save.addEventListener('click',()=>openIssueLibrary(event));
  actions.append(copy,search,save);
  const level=event.kind==='login_failed'?'error':event.kind;
  for(const issue of knownIssues.filter(issue=>(issue.severity==='all'||issue.severity===level)&&event.raw.toLocaleLowerCase().includes(issue.phrase.toLocaleLowerCase()))){
    const match=el('button',`Resolution: ${issue.title}`,'known-match');match.type='button';match.addEventListener('click',()=>openIssueLibrary(null,issue.id));actions.append(match);
  }
  return actions;
}
function logUploadBody(payload, source) {
  const metadata = {...payload, Encoding: source.encoding,
    Files: source.files.map(file => ({Name: file.name, Size: file.size}))};
  const manifest = new TextEncoder().encode(JSON.stringify(metadata));
  const prefix = new ArrayBuffer(4);
  new DataView(prefix).setUint32(0, manifest.length);
  return new Blob([prefix, manifest, ...source.files], {type: 'application/vnd.ras.logs'});
}
function renderAnalysisItems(){
  if(!analysisData)return;
  const query=$('analysis-search').value.trim().toLocaleLowerCase();const severity=$('analysis-severity').value;
  const fileId=$('analysis-file').value;
  const available=[...analysisData.issues];
  if(selectedAnalysisIssue&&!available.some(item=>item.id===selectedAnalysisIssue.id))available.push(selectedAnalysisIssue);
  const items=available.filter(item=>(!fileId||item.file_id===fileId)&&(severity==='all'||(severity?item.severity===severity:['error','warning'].includes(item.severity)))&&(!query||`${item.raw} ${item.user} ${item.host} ${item.file}`.toLocaleLowerCase().includes(query)));
  const rows=items.map(item=>{
    const row=el('tr');row.id=`analysis-row-${item.id}`;row.tabIndex=-1;if(selectedAnalysisIssue?.id===item.id)row.className='analysis-selected';const level=el('td');level.append(el('span',item.severity==='error'?'Error':item.severity==='warning'?'Warning':'Information',`badge ${item.severity}`));
    const location=el('td',item.timestamp||'Timestamp unavailable');location.append(el('small',item.file));location.append(el('small',`Line ${item.line.toLocaleString()}`));
    const person=el('td',item.user||'Unassigned');person.append(el('small',item.host||'Unknown host'));
    const message=el('td');message.append(el('div',item.raw,'analysis-raw'),errorActions({raw:item.raw,kind:item.severity}));
    if(item.severity==='error'||item.severity==='warning'){
      const context=el('button','View in full log');context.type='button';
      context.addEventListener('click',async()=>{
        if(analysisRunning || busyChanging)return;
        $('analysis-file').value=item.file_id;$('analysis-severity').value='all';$('analysis-period').value='all';$('analysis-search').value='';
        analysisOffset=Math.floor((item.line-1)/500)*500;
        if(await runAnalysis(analysisSource,true)){
          selectedAnalysisIssue=item;renderAnalysisItems();
          const target=$(`analysis-row-${item.id}`);target?.scrollIntoView({block:'center'});target?.focus({preventScroll:true});
        }
      });message.append(context);
    }
    row.append(level,location,person,message);return row;
  });
  $('analysis-items').replaceChildren(...rows);$('analysis-empty').hidden=!!rows.length;
  $('analysis-summary').textContent=`Showing ${analysisData.matched?analysisData.offset+1:0}–${analysisData.offset+analysisData.issues.length} of ${analysisData.matched.toLocaleString()} matching entries`;
  $('analysis-prev').disabled=analysisData.offset===0;
  $('analysis-next').disabled=analysisData.offset+analysisData.issues.length>=analysisData.matched;

}
function renderAnalysis(data){
  analysisData=data;$('analysis-results').hidden=false;
  $('summary-logins').textContent=data.stats.logins.toLocaleString();
  $('summary-failed').textContent=data.stats.failed.toLocaleString();
  $('summary-entities').textContent=`${data.stats.users.toLocaleString()} / ${data.stats.hosts.toLocaleString()}`;
  $('analysis-total').textContent=data.stats.total.toLocaleString();$('analysis-errors').textContent=data.stats.errors.toLocaleString();
  $('analysis-warnings').textContent=data.stats.warnings.toLocaleString();$('analysis-information').textContent=data.stats.information.toLocaleString();
  selectedAnalysisIssue=null;
  $('analysis-file').replaceChildren(new Option('All files',''),...data.file_options.map(file=>new Option(`${file.name} (file ${Number(file.id)+1})`,file.id)));
  renderAnalysisGroups();renderAnalysisItems();
}
function renderAnalysisGroups(){
  if(!analysisData)return;
  const fileId=$('analysis-file').value;
  const groups=fileId?(analysisData.file_groups[fileId]||[]):analysisData.groups;
  const cards=groups.map(group=>{
    const card=el('button',undefined,'analysis-group');card.type='button';
    const content=el('div');content.append(el('strong',group.message),el('small',`Last occurred: ${group.latest.timestamp||'Timestamp unavailable (last matching line)'}`),el('small',`Latest: ${group.latest.file}, line ${group.latest.line.toLocaleString()}`),el('small',`Found in: ${Object.values(group.files).join(', ')}`));
    card.append(el('span',group.severity==='error'?'Error':'Warning',`badge ${group.severity}`),content,el('span',`${group.count.toLocaleString()}×`,'group-count'));
    card.addEventListener('click',()=>{
      selectedAnalysisIssue=group.latest;$('analysis-search').value='';$('analysis-severity').value='';renderAnalysisItems();
      const row=$( `analysis-row-${group.latest.id}` );row?.scrollIntoView({block:'center',behavior:'smooth'});row?.focus({preventScroll:true});
    });return card;
  });
  $('analysis-groups').replaceChildren(...cards);if(!cards.length)$('analysis-groups').append(el('p','No errors or warnings were found in these files.','note'));
}
let analysisSource=null, analysisRunning=false, analysisOffset=0, analysisRefreshPending=false;
function analysisWindow(){
  const period=$('analysis-period').value;if(period==='all')return {};
  const end=new Date(),start=new Date(end);
  if(period==='today')start.setHours(0,0,0,0);else start.setTime(end.getTime()-Number(period)*3600000);
  const local=date=>`${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}-${String(date.getDate()).padStart(2,'0')}T${String(date.getHours()).padStart(2,'0')}:${String(date.getMinutes()).padStart(2,'0')}:${String(date.getSeconds()).padStart(2,'0')}`;
  return {Since:local(start),Until:local(end)};
}
function uploadWithProgress(url, body, contentType, status, progress, nextPhase){
  progress.hidden=false;progress.max=100;progress.value=0;
  return new Promise((resolve,reject)=>{
    const xhr=new XMLHttpRequest();
    xhr.open('POST',url);
    xhr.timeout=900000;
    xhr.setRequestHeader('Content-Type',contentType);
    xhr.setRequestHeader('X-Logwatch-Analyze','1');
    xhr.upload.onprogress=event=>{
      if(event.lengthComputable){
        progress.value=Math.round(event.loaded/event.total*100);
        status.textContent='Uploading: '+progress.value+'%';
      }
    };
    xhr.upload.onload=()=>{progress.removeAttribute('value');status.textContent=nextPhase;};
    xhr.onload=()=>resolve(new Response(xhr.responseText,{status:xhr.status}));
    xhr.onerror=()=>reject(new Error('Upload connection failed.'));
    xhr.ontimeout=()=>reject(new Error('Upload or analysis timed out.'));
    xhr.send(body);
  });
}
async function runAnalysis(source,preserve=false){
  if(analysisRunning){analysisRefreshPending=true;return false;}
  if(!source || (busyChanging && !source.files))return false;
  analysisRunning=true;updateControls();for(const id of ['analysis-file','analysis-search','analysis-severity'])$(id).disabled=true;$('analyze-files').disabled=true;$('analysis-period').disabled=true;
  $('analysis-progress').hidden=false;$('analysis-progress').removeAttribute('value');
  $('analysis-message').textContent='Reading and analysing the selected date range…';
  const previous={file:$('analysis-file').value,search:$('analysis-search').value,severity:$('analysis-severity').value};
  try{
    let payload={...analysisWindow(),Severity:previous.severity,Query:previous.search,FileId:preserve?previous.file:'',Offset:preserve?analysisOffset:0,PageSize:500},url='/api/analyze';
    let body, contentType;
    if(source.indexed){
      url='/api/investigation/query';
      Object.assign(payload,{token:source.token,log_id:source.log_id || ''});
      body=JSON.stringify(payload);
      contentType='application/json';
    }else if(source.files){
      payload.Indexed=true;
      body=logUploadBody(payload,source);
      contentType=body.type;
    }else{
      url='/api/bundle/analyze';
      Object.assign(payload,{token:source.token,log_id:source.log_id});
      body=JSON.stringify(payload);
      contentType='application/json';
    }
    const response=source.files ? await uploadWithProgress(url,body,contentType,$('analysis-message'),$('analysis-progress'),'Upload complete. Indexing log entries…') : await fetch(url,{method:'POST',headers:{'Content-Type':contentType,'X-Logwatch-Analyze':'1'},body,signal:AbortSignal.timeout(900000)});
    if(!response.ok)throw new Error((await response.text()).replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim());
    const data=await response.json();
    if(source.files)countSession(true);
    analysisSource={indexed:true,token:data.investigation,log_id:source.log_id};
    trackInvestigation(data.investigation,data.expires_at);appliedAnalysisPeriod=$('analysis-period').value;renderAnalysis(data);
    if(preserve){$('analysis-file').value=previous.file;renderAnalysisGroups();renderAnalysisItems();}
    $('bundle-source').hidden=!data.bundle_source;
    if(data.bundle_source)$('bundle-source').textContent=`Server: ${data.bundle_source.server} · Source: ${data.bundle_source.path}`;
    $('analysis-message').textContent=`${data.stats.total.toLocaleString()} lines in the selected date range from ${data.files} file(s).${data.unknown_timestamps?` ${data.unknown_timestamps.toLocaleString()} lines without a readable timestamp excluded; choose All logs to include them.`:''}`;
    return true;
  }catch(error){$('analysis-message').textContent=`Analysis failed: ${error.message}. Previous results remain displayed.`;return false;}
  finally{$('analysis-progress').hidden=true;analysisRunning=false;updateControls();for(const id of ['analysis-file','analysis-search','analysis-severity'])$(id).disabled=false;$('analyze-files').disabled=false;$('analysis-period').disabled=false;if(analysisRefreshPending){analysisRefreshPending=false;runAnalysis(analysisSource,true);}}
}
async function analyzeFiles(){
  const files=[...$('analysis-files').files];if(!files.length){$('analysis-message').textContent='Choose at least one log file.';return;}
  if(files.length>10){$('analysis-message').textContent='Choose no more than 10 files.';return;}
  if(files.reduce((total,file)=>total+file.size,0)>1024**3){$('analysis-message').textContent='Choose files totalling no more than 1 GiB.';return;}
  busyChanging=true;updateControls();
  try{if(await prepareReplacement()){
    $('bundle-file').value='';
    await runAnalysis({files,encoding:$('analysis-encoding').value});
  }}finally{busyChanging=false;updateControls();}
}
let appliedAnalysisPeriod='all';
$('analysis-period').addEventListener('change',async()=>{
  if(!analysisSource)return;
  analysisOffset=0;
  if(await runAnalysis(analysisSource,true))appliedAnalysisPeriod=$('analysis-period').value;
  else $('analysis-period').value=appliedAnalysisPeriod;
});

function addActivityRuleEditor(rule={Kind:'login',Pattern:''}){
  const card=el('div',undefined,'activity-rule-editor');
  const kindLabel=el('label');kindLabel.append(el('span','Event type'));
  const select=el('select');select.className='activity-kind';
  for(const value of ['login','connection','logout']){const option=el('option',labels[value]);option.value=value;option.selected=value===(rule.Kind||'login');select.append(option);}
  kindLabel.append(select);
  const patternLabel=el('label');patternLabel.append(el('span','Python regular expression'));
  const pattern=el('textarea');pattern.className='activity-pattern';pattern.rows=3;pattern.value=rule.Pattern||'';pattern.placeholder="\\bUser '(?P<user>[^']+)' connected to host '(?P<host>[^']+)'";patternLabel.append(pattern);
  const remove=el('button','Remove rule','remove-source');remove.type='button';remove.addEventListener('click',()=>card.remove());
  card.append(kindLabel,patternLabel,remove);$('activity-rule-list').append(card);
}
function fillParserForm(settings){
  $('error-strings').value=settings.ErrorSearchStrings.join('\n');
  $('activity-rule-list').replaceChildren();
  for(const rule of settings.ActivityRules)addActivityRuleEditor(rule);
}
$('parser-defaults').addEventListener('click',async()=>{
  try {
    const response=await fetch('/api/settings/defaults');
    if(!response.ok)throw new Error('Could not load parser defaults.');
    fillParserForm(await response.json());
    $('admin-message').textContent='Defaults loaded. Edit them or select Save and apply for new analyses.';
  } catch(error){$('admin-message').textContent=error.message;}
});
async function openAdmin(){
  $('admin-message').textContent='Loading settings…';
  $('activity-rule-list').replaceChildren();
  $('admin-dialog').showModal();
  try{
    const response=await fetch('/api/settings',{signal:AbortSignal.timeout(10000)});
    if(!response.ok)throw new Error('Could not load settings.');
    const settings=await response.json();
    fillParserForm(settings);
    $('save-admin').disabled=!settings.CanSave;
    $('admin-message').textContent=settings.CanSave?'Changes apply to newly indexed logs.':'Settings are read-only in this instance.';
  }catch(error){$('admin-message').textContent=error.message;$('save-admin').disabled=true;}
}
function closeAdmin(){$('admin-dialog').close();}
$('open-admin').addEventListener('click',openAdmin);
$('close-admin').addEventListener('click',closeAdmin);
$('cancel-admin').addEventListener('click',closeAdmin);
$('add-activity-rule').addEventListener('click',()=>addActivityRuleEditor());
$('analyze-files').addEventListener('click',analyzeFiles);
function refreshAnalysisFilter(){analysisOffset=0;selectedAnalysisIssue=null;if(analysisSource)runAnalysis(analysisSource,true);}
$('analysis-file').addEventListener('change',refreshAnalysisFilter);
$('analysis-severity').addEventListener('change',refreshAnalysisFilter);
let analysisSearchTimer;
$('analysis-search').addEventListener('input',()=>{clearTimeout(analysisSearchTimer);analysisSearchTimer=setTimeout(refreshAnalysisFilter,500);});
$('analysis-prev').addEventListener('click',()=>{if(analysisRunning || busyChanging)return;analysisOffset=Math.max(0,analysisData.offset-500);runAnalysis(analysisSource,true);});
$('analysis-next').addEventListener('click',()=>{if(analysisRunning || busyChanging)return;analysisOffset=analysisData.offset+500;runAnalysis(analysisSource,true);});
$('admin-form').addEventListener('submit',async event=>{
  event.preventDefault();
  const ErrorSearchStrings=$('error-strings').value.split('\n').map(value=>value.trim()).filter(Boolean);
  const ActivityRules=[...document.querySelectorAll('.activity-rule-editor')].map(card=>({
    Kind:card.querySelector('.activity-kind').value,
    Pattern:card.querySelector('.activity-pattern').value.trim()
  }));
  $('save-admin').disabled=true;$('admin-message').textContent='Saving…';
  try{
    const response=await fetch('/api/settings',{method:'POST',headers:{'Content-Type':'application/json','X-Logwatch-Admin':'1'},body:JSON.stringify({ErrorSearchStrings,ActivityRules}),signal:AbortSignal.timeout(10000)});
    if(!response.ok){const detail=await response.text();throw new Error(`Save failed (${response.status}). ${detail.replace(/<[^>]+>/g,' ').replace(/\s+/g,' ').trim()}`);}
    $('admin-message').textContent='Saved. Parsing settings apply to the next analysis.';
    setTimeout(()=>{closeAdmin();},700);
  }catch(error){$('admin-message').textContent=error.message;$('save-admin').disabled=false;}
});
let bundleData=null;
function isPrimaryRasLog(path){
  const filename = path.split(/[\\/]/).pop();
  return /^(?:controller|vdiagent|gateway|tsagent)(?:$|[._ -])/i.test(filename);
}
async function loadBundleOverview(token){
  const fields = {'analysis-total':'total','summary-logins':'logins','summary-failed':'failed','analysis-errors':'errors'};
  const count=bundleData.servers.reduce((n,server)=>n+server.logs.length,0);
  $('bundle-ranking').hidden=false;
  $('bundle-top-logs').replaceChildren(el('li','Waiting for the first log with errors.'));
  $('bundle-summary-status').textContent='Starting bundle overview… You can open a log now.';
  for(const id of Object.keys(fields))$('bundle-'+id).textContent='0';
  $('bundle-summary-entities').textContent='0 / 0';
  const bar=$('overview-progress');
  bar.hidden=false;bar.max=count || 1;bar.value=0;
  try{
    while(bundleData?.token===token){
    const response=await fetch('/api/bundle/overview',{method:'POST',headers:{'Content-Type':'application/json','X-Logwatch-Analyze':'1'},body:JSON.stringify({token})});
    if(!response.ok)throw new Error('Could not calculate bundle totals.');
    const result=await response.json();
    if(bundleData?.token!==token)return;
    for(const [id,key] of Object.entries(fields))$('bundle-'+id).textContent=result.stats[key].toLocaleString();
    $('bundle-summary-entities').textContent=`${result.stats.users.toLocaleString()} / ${result.stats.hosts.toLocaleString()}`;
    $('bundle-top-logs').replaceChildren();
    for(const log of result.top_logs){
      const item=el('li'), button=el('button');
      button.type='button';
      button.append(el('strong',log.server+' · '+log.name),el('span',log.errors.toLocaleString()+(log.errors===1?' error':' errors')),el('small',log.path));
      button.addEventListener('click',async()=>{
        if(analysisRunning || busyChanging || bundleData?.token!==token)return;
        $('bundle-server').value=log.server;renderBundleLogs();
        $('analysis-period').value='all';$('analysis-search').value='';$('analysis-severity').value='error';
        if(await runAnalysis({token,log_id:log.id}))$('analysis-results').scrollIntoView({block:'start'});
      });
      item.append(button);$('bundle-top-logs').append(item);
    }
    if(!result.top_logs.length)$('bundle-top-logs').append(el('li',result.done?'No errors found in the analysed logs.':'No errors found in completed logs yet.'));
    bar.value=result.processed;
    $('bundle-summary-status').textContent=[
      result.done?'Overview complete.':'Running totals.',
      result.processed+' of '+result.count+' logs processed.',
      result.current?'Indexing '+result.current+'.':'',
      result.omitted?result.omitted+' logs omitted.':'',result.error || ''
    ].filter(Boolean).join(' ');
    if(result.done){bar.hidden=true;break;}
    await new Promise(resolve=>setTimeout(resolve,1500));
    }
  }catch(error){
    if(bundleData?.token===token)$('bundle-summary-status').textContent=error.message+' Select a log to inspect it individually.';
  }
}
function renderBundleLogs(){
  if(!bundleData)return;
  const server=$('bundle-server').value;
  const servers=bundleData.servers.filter(s=>!server||s.name===server);
  const logs=servers.flatMap(s=>s.logs);
  $('bundle-count').textContent=`${logs.length} logs across ${servers.length} server groups`;
  const table=el('table');const head=el('thead');const header=el('tr');
  for(const title of ['Server','Log / archive path','Size',''])header.append(el('th',title));head.append(header);table.append(head);
  const body=el('tbody');
  for(const log of logs){
    const row=el('tr');
    const name=el('td');
    const filename=el('span',log.name);
    if(isPrimaryRasLog(log.name)){
      filename.className='primary-log-name';
      filename.title='Commonly reviewed RAS log';
    }
    name.append(filename,el('small',log.path));
    const action=el('td');const button=el('button','Analyse log');button.type='button';
    button.addEventListener('click',async()=>{
      if(analysisRunning || busyChanging)return;
      button.disabled=true;
      try{
        if(await runAnalysis({token:bundleData.token,log_id:log.id})){
          $('bundle-status').textContent='Analysis complete. Select another server or log to continue.';
          $('analysis-results').scrollIntoView({block:'start',behavior:'smooth'});
        }
      }finally{button.disabled=false;}
    });action.append(button);row.append(el('td',log.server),name,el('td',`${(log.size/1024/1024).toFixed(2)} MiB`),action);body.append(row);
  }
  table.append(body);$('bundle-logs').replaceChildren(table);
}
$('bundle-server').addEventListener('change',renderBundleLogs);
let investigationToken=null, expiryTimer=null, busyChanging=false;
function updateControls(){
  const busy=analysisRunning || busyChanging;
  $('clear-investigation').disabled=busy || !(investigationToken || $('analysis-files').files.length || $('bundle-file').files.length);
  $('bundle-upload').disabled=busy;
  $('analyze-files').disabled=busy;
}
function resetView(clearInputs){
  clearTimeout(expiryTimer);
  clearTimeout(analysisSearchTimer);
  try{sessionStorage.removeItem('ras.active-investigation');}catch{}
  investigationToken=null;bundleData=null;analysisSource=null;analysisData=null;
  selectedAnalysisIssue=null;analysisOffset=0;analysisRefreshPending=false;
  $('bundle-browser').hidden=true;$('bundle-logs').replaceChildren();
  $('bundle-server').replaceChildren();$('bundle-count').textContent='';
  $('bundle-source').hidden=true;$('bundle-source').textContent='';
  $('analysis-results').hidden=true;$('analysis-items').replaceChildren();$('analysis-groups').replaceChildren();
  $('analysis-file').replaceChildren(new Option('All files',''));
  $('analysis-search').value='';$('analysis-severity').value='';$('analysis-period').value='all';appliedAnalysisPeriod='all';
  $('analysis-summary').textContent='';$('analysis-message').textContent='';
  $('bundle-status').textContent='';$('investigation-expiry').textContent='No active investigation';
  if(clearInputs){$('analysis-files').value='';$('bundle-file').value='';}
  updateControls();
}
function trackInvestigation(token,expiresAt){
  investigationToken=token;
  try{sessionStorage.setItem('ras.active-investigation',JSON.stringify({token,expiresAt}));}catch{}
  clearTimeout(expiryTimer);
  const deadline=new Date(expiresAt*1000);
  $('investigation-expiry').textContent='Investigation expires '+deadline.toLocaleString();
  expiryTimer=setTimeout(()=>{
    if(investigationToken===token){
      resetView(true);
      $('investigation-expiry').textContent='Investigation expired. Upload again to start a new one.';
    }
  },Math.max(0,deadline-Date.now()));
  updateControls();
}
async function removeInvestigation(clearInputs){
  if(investigationToken){
    const response=await fetch('/api/investigation/clear',{method:'POST',
      headers:{'Content-Type':'application/json','X-Logwatch-Analyze':'1'},
      body:JSON.stringify({token:investigationToken})});
    if(!response.ok)throw new Error('Server cleanup failed. Please retry Clear investigation.');
  }
  resetView(clearInputs);
}
async function prepareReplacement(){
  if(!investigationToken)return true;
  try{await removeInvestigation(false);return true;}
  catch(error){$('investigation-expiry').textContent=error.message;return false;}
}
// Keep the clear control available after a reload of this tab.
try {
  const previous=JSON.parse(sessionStorage.getItem('ras.active-investigation'));
  if(previous && previous.expiresAt*1000>Date.now())trackInvestigation(previous.token,previous.expiresAt);
} catch { /* Optional when session storage is restricted. */ }
$('clear-investigation').addEventListener('click',async()=>{
  busyChanging=true;updateControls();
  try{await removeInvestigation(true);}
  catch(error){$('investigation-expiry').textContent=error.message;}
  finally{busyChanging=false;updateControls();}
});
for(const id of ['analysis-files','bundle-file'])$(id).addEventListener('change',updateControls);
$('bundle-upload').addEventListener('click',async()=>{
  const file=$('bundle-file').files[0];if(!file){$('bundle-status').textContent='Choose a support bundle first.';return;}
  if(file.size>1024**3){$('bundle-status').textContent='The compressed bundle exceeds 1 GiB.';return;}
  busyChanging=true;updateControls();$('bundle-status').textContent='Uploading and inspecting nested archives…';
  try{
    if(!await prepareReplacement())return;
    $('analysis-files').value='';
    const response=await uploadWithProgress('/api/bundle',file,'application/octet-stream',$('bundle-status'),$('bundle-progress'),'Upload complete. Inspecting nested archives…');
    if(!response.ok)throw new Error(await response.text());
    bundleData=await response.json();countSession(true);$('bundle-browser').hidden=false;trackInvestigation(bundleData.token,bundleData.expires_at);
    $('bundle-server').replaceChildren(new Option('All servers',''),...bundleData.servers.map(s=>new Option(`${s.name} (${s.logs.length} logs)`,s.name)));
    renderBundleLogs();loadBundleOverview(bundleData.token);$('bundle-status').textContent=`Bundle ready. ${bundleData.skipped} non-text entries skipped. Choose a server, then Analyse log.`;
  }catch(error){$('bundle-status').textContent=`Bundle upload failed: ${error.message.replace(/<[^>]+>/g,' ')}`;}
  finally{$('bundle-progress').hidden=true;busyChanging=false;updateControls();}
});

let editingIssueId=null;
function editKnownIssue(issue={}){
  editingIssueId=issue.id??null;
  $('library-editor-title').textContent=issue.id?'Edit issue and resolution':'New issue';
  for(const key of ['title','phrase','notes','links','sample'])$('kb-'+key).value=issue[key]||'';
  $('kb-severity').value=issue.severity||'all';
}
function renderKnownIssues(){
  const query=$('library-search').value.toLocaleLowerCase();
  const cards=knownIssues.filter(issue=>`${issue.title} ${issue.phrase} ${issue.notes} ${issue.links}`.toLocaleLowerCase().includes(query)).map(issue=>{
    const card=el('article',undefined,'known-card');card.append(el('h3',issue.title),el('p',`Matches: ${issue.phrase} · ${issue.severity}`),el('p',issue.notes,'resolution-notes'));
    for(const url of issue.links.split(/\r?\n/).filter(Boolean)){
      try{const parsed=new URL(url);if(!['http:','https:'].includes(parsed.protocol))continue;}catch{continue;}
      const link=el('a',url);link.href=url;link.target='_blank';link.rel='noopener noreferrer';card.append(link);
    }
    const edit=el('button','Edit issue');edit.type='button';edit.addEventListener('click',()=>{editKnownIssue(issue);$('library-form').scrollIntoView({block:'nearest'});});card.append(edit);return card;
  });
  $('library-list').replaceChildren(...cards);if(!cards.length)$('library-list').append(el('p','No saved issues match.'));
}
async function loadKnownIssues(){
  const response=await fetch('/api/known-issues',{signal:AbortSignal.timeout(10000)});
  if(!response.ok)throw new Error('Could not load the issue library.');
  knownIssues=await response.json();renderKnownIssues();if(analysisData)renderAnalysisItems();
}
async function openIssueLibrary(event=null,id=null){
  $('library-dialog').showModal();$('library-status').textContent='Loading…';
  try{
    await loadKnownIssues();
    const issue=knownIssues.find(issue=>issue.id===id);
    if(issue){$('library-search').value=issue.title;editKnownIssue(issue);}
    else if(event){
      const phrase=event.raw.replace(/^\[[EWI][^\]]*\]\s*/i,'').replace(/^\d{2}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+-\s+/,'').trim().slice(0,2000);
      $('library-search').value='';editKnownIssue({title:phrase.slice(0,200),phrase,sample:event.raw.slice(0,10000),severity:event.kind==='login_failed'?'error':['error','warning','info'].includes(event.kind)?event.kind:'all'});
    }else{$('library-search').value='';editKnownIssue();}
    renderKnownIssues();$('library-status').textContent='';
  }catch(error){$('library-status').textContent=error.message;}
}
$('open-library').addEventListener('click',()=>openIssueLibrary());
$('library-close').addEventListener('click',()=>$('library-dialog').close());
$('library-new').addEventListener('click',()=>editKnownIssue());
$('library-search').addEventListener('input',renderKnownIssues);
$('library-form').addEventListener('submit',async event=>{
  event.preventDefault();$('library-save').disabled=true;
  const payload={id:editingIssueId};for(const key of ['title','phrase','severity','notes','links','sample'])payload[key]=$('kb-'+key).value;
  try{
    const response=await fetch('/api/known-issues',{method:'POST',headers:{'Content-Type':'application/json','X-Logwatch-Admin':'1'},body:JSON.stringify(payload),signal:AbortSignal.timeout(10000)});
    if(!response.ok)throw new Error((await response.text()).replace(/<[^>]+>/g,' '));
    const result=await response.json();knownIssues=result.issues;editingIssueId=result.id;$('library-search').value='';renderKnownIssues();if(analysisData)renderAnalysisItems();$('library-status').textContent='Saved. Matching resolutions are now shown beside log messages.';
  }catch(error){$('library-status').textContent=error.message;}finally{$('library-save').disabled=false;}
});
loadKnownIssues().catch(error=>{$('library-status').textContent=error.message;});


function showSessionNotice() {
  const key = 'ras-log-analyser.disclaimer.v1';
  const dialog = $('session-notice');
  try {
    if (sessionStorage.getItem(key) === 'seen') return;
  } catch {
    // Browsers with restricted storage can still display and dismiss the notice.
  }
  $('session-notice-text').textContent = $('notice-text').textContent;
  dialog.addEventListener('close', () => {
    try { sessionStorage.setItem(key, 'seen'); } catch { /* Storage unavailable. */ }
  }, { once: true });
  dialog.showModal();
}
showSessionNotice();
