const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const html=fs.readFileSync('dashboard/frontend/rsyslog.html','utf8');
const source=html.slice(html.indexOf('async function refreshAll('),html.indexOf('async function viewEvent('));
const requests=[],loaded=[];
const context=vm.createContext({refreshBusy:false,anchorId:null,activeView:'logs',collectionStatus:{textContent:''},
  fetch:async(url,options)=>{requests.push([url,options]);return {ok:true,json:async()=>({agent:{status:'sent',sent:3},normalized:3})};},
  loadHosts:async()=>loaded.push('hosts'),loadActiveView:async()=>loaded.push('logs')});
vm.runInContext(source,context);
(async()=>{
  await vm.runInContext('refreshAll()',context);
  assert.equal(requests.length,0,'Automatic view polling must not force agent delivery');
  await vm.runInContext('refreshAll(true)',context);
  assert.equal(requests[0][0],'/api/collection/refresh');assert.equal(requests[0][1].method,'POST');
  assert.ok(context.collectionStatus.textContent.includes('3건'));
  assert.ok(html.includes('},300000)'));assert.ok(html.includes('자동 새로고침(5분)'));
  console.log('Manual agent flush and five-minute automatic polling passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
