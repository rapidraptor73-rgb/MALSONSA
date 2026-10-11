const assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const html=fs.readFileSync(path.join(__dirname,'../dashboard/frontend/rsyslog.html'),'utf8');
const start=html.indexOf('function renderEvents(){'),end=html.indexOf('async function loadHosts(){',start);
assert.ok(start>=0 && end>start);
let writes=0,error=false,opened=0;
const age={dataset:{age:'2026-10-11T00:00:00Z'},textContent:''};
const body={querySelector:()=>error?{}:null,querySelectorAll:()=>[age]};
Object.defineProperty(body,'innerHTML',{set(value){writes++;error=false;this.content=value;}});
const context=vm.createContext({
  allEvents:[{id:1,time:'2026-10-11T00:00:00Z',event:'AUTH_FAILURE'}],
  previousRenderKey:null,previousNewestId:null,eventsBody:body,
  activeView:'logs',
  eventCount:{},apiLoaded:{},badTimeCount:{},lastReceived:{},lastAge:{},
  parseTime:value=>new Date(value),eventTime:event=>event.time,sortNewest:()=>0,
  ageText:()=> '지금',displayTime:()=> '00:00:00',esc:value=>String(value??''),
  openDetails:()=>{opened++;return new Set();},restoreDetails:()=>{},
  SiemRisk:{eventRiskHtml:()=> 'risk',detectionHtml:()=> 'detection'},
});
vm.runInContext('function filteredEvents(){return allEvents;}',context);
vm.runInContext(html.slice(start,end),context);
vm.runInContext('renderEvents()',context);
assert.equal(writes,1);assert.equal(opened,1);
vm.runInContext('renderEvents()',context);
assert.equal(writes,1,'Unchanged polling must retain table DOM and expanded evidence');
assert.equal(age.textContent,'지금','Relative ages still update');
context.allEvents[0].held=true;
vm.runInContext('renderEvents()',context);
assert.equal(writes,2,'Hold/risk data changes must render');
error=true;
vm.runInContext('renderEvents()',context);
assert.equal(writes,3,'Successful data must replace an API error even if unchanged');
console.log('Stable collection DOM, age refresh, changed data and error recovery passed');
