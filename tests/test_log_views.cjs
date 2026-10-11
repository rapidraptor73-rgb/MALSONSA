const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../dashboard/frontend/rsyslog.html'),'utf8');
const escape=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
const body={innerHTML:'',querySelector:()=>null,querySelectorAll:()=>[]};
const sourceContext=vm.createContext({document:{getElementById:()=>body},previousSourceKey:null,esc:escape,
  displayTime:()=>'-',ageText:()=>'-',SiemRisk:{scoreBadge:score=>'risk '+score}});
const from=html.indexOf('function renderSources(result){'),to=html.indexOf('async function viewSource(ip){',from);
vm.runInContext(html.slice(from,to),sourceContext);
sourceContext.result={page:1,per_page:50,sources:[{src_ip:'<img src=x onerror=alert(1)>',event_count:35,
  risk_score:155,self_score:20,sample_count:20,critical_count:3,suspicious_count:35,host_count:1,
  attacks:['<script>bad</script>'],last_seen:'2026-10-11T00:00:00Z'}]};
vm.runInContext('renderSources(result)',sourceContext);
assert.ok(!body.innerHTML.includes('<img'));assert.ok(!body.innerHTML.includes('<script>'));
assert.ok(body.innerHTML.includes('&lt;img'));assert.ok(body.innerHTML.includes('최근 20건 최고 점수'));
assert.ok(body.innerHTML.includes('35건'));

(async()=>{
  const pending=[],elements=new Map();
  const element=id=>{if(!elements.has(id))elements.set(id,{value:id==='timeRange'?'300':'',textContent:'',innerHTML:''});return elements.get(id);};
  let sourceRenders=0,savedRenders=0;
  const context=vm.createContext({activeView:'saved',viewRequest:0,savedPage:1,sourcePage:1,savedEvents:[],
    eventsBody:element('eventsBody'),document:{getElementById:element},URLSearchParams,
    scopeParams:()=>new URLSearchParams(),fetch:url=>new Promise(resolve=>pending.push({url,resolve})),
    updateServerClock:()=>{},updatePager:()=>{},renderEvents:()=>savedRenders++,renderSources:()=>sourceRenders++,
    apiLoaded:{},badTimeCount:{},lastReceived:{},lastAge:{},esc:escape});
  const start=html.indexOf('async function loadActiveView(){'),end=html.indexOf('function renderSources(result){',start);
  vm.runInContext(html.slice(start,end),context);
  const old=vm.runInContext('loadActiveView()',context);
  context.activeView='sources';const fresh=vm.runInContext('loadActiveView()',context);
  pending[1].resolve({ok:true,json:async()=>({sources:[],page:1,total:0,event_count:0})});await fresh;
  pending[0].resolve({ok:true,json:async()=>({events:[{id:99}],page:1,total:1})});await old;
  assert.equal(sourceRenders,1);assert.equal(savedRenders,0);
  assert.equal(context.savedEvents.length,0,'Late saved-log response must not replace the source tab');
  console.log('Source view escaping, sampling labels and stale tab response protection passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
