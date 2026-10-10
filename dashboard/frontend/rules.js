'use strict';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
const fields = {message:'메시지',program:'프로그램',event:'이벤트 유형',src_ip:'출발지 SRC',dst_ip:'목적지 DST',user:'사용자',mitre:'MITRE'};
let rules = [], editing = null;
async function api(path,method='GET',body){
  const response=await fetch(path,{method,headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),cache:'no-store'});
  const result=await response.json(); if(!response.ok) throw new Error(result.error || `HTTP ${response.status}`); return result;
}
function status(message,error=false){$('status').textContent=message;$('status').classList.toggle('bad',error);}
function addCondition(value={field:'message',operator:'contains',value:''}){
  if($('conditions').children.length>=8){status('조건은 최대 8개입니다.',true);return;}
  const row=document.createElement('div'); row.className='condition-row';
  row.innerHTML=`<select aria-label="조건 필드">${Object.entries(fields).map(([key,label])=>`<option value="${key}">${label}</option>`).join('')}</select><select aria-label="비교 방식"><option value="contains">포함</option><option value="equals">정확히 일치</option></select><input aria-label="조건 값" required maxlength="256" placeholder="예: failed password"><button type="button" aria-label="조건 삭제">삭제</button>`;
  row.children[0].value=value.field;row.children[1].value=value.operator;row.children[2].value=value.value;
  row.children[3].onclick=()=>{row.remove();$('previewResult').textContent='조건이 변경되었습니다. 다시 테스트하세요.';};$('conditions').append(row);
}
function payload(){
  return {host_id:Number($('hostId').value),name:$('ruleName').value,attack:$('attack').value,points:Number($('points').value),reason:$('reason').value,enabled:$('enabled').checked,match_mode:$('matchMode').value,min_hits:Number($('minHits').value),window_seconds:Number($('windowSeconds').value),group_by:$('groupBy').value,conditions:[...$('conditions').children].map(row=>({field:row.children[0].value,operator:row.children[1].value,value:row.children[2].value}))};
}
function reset(){editing=null;$('ruleForm').reset();$('conditions').replaceChildren();addCondition();$('editorTitle').textContent='룰셋 추가';$('saveRule').textContent='룰 저장';$('previewResult').textContent='수집 로그 ID를 입력해 저장 전 테스트하세요.';}
function edit(rule){
  editing=rule.id; for(const [id,key] of Object.entries({hostId:'host_id',ruleName:'name',attack:'attack',points:'points',reason:'reason',matchMode:'match_mode',minHits:'min_hits',windowSeconds:'window_seconds',groupBy:'group_by'})) $(id).value=rule[key];
  $('enabled').checked=!!rule.enabled;$('conditions').replaceChildren();rule.conditions.forEach(addCondition);$('editorTitle').textContent=`룰 #${rule.id} 수정`;$('saveRule').textContent='변경 저장';$('previewResult').textContent='수정 중인 룰을 저장 전 테스트할 수 있습니다.';$('ruleForm').scrollIntoView({behavior:'smooth',block:'start'});
}
function render(){
  const visible=rules.filter(rule=>!$('hostFilter').value||rule.host_id===Number($('hostFilter').value));$('ruleCount').textContent=visible.length;
  $('ruleList').innerHTML=visible.map(rule=>`<article class="rule-item"><div class="toolbar"><b>${esc(rule.name)}</b><span class="tag ${rule.enabled&&rule.host_enabled?'ok':'bad'}">${rule.enabled&&rule.host_enabled?'활성':rule.host_enabled?'비활성':'에이전트 비활성'}</span></div><span class="subtext">${esc(rule.host_name||'삭제된 에이전트')} · ${esc(rule.host_ip||'')} · 룰 #${rule.id}</span><h3>${esc(rule.attack)} 의심 · +${rule.points}점</h3><p>${esc(rule.reason)}</p><div class="rule-conditions">${rule.conditions.map(c=>`${esc(fields[c.field])} ${c.operator==='contains'?'포함':'일치'} <code>${esc(c.value)}</code>`).join(rule.match_mode==='all'?' AND ':' OR ')}</div><p class="subtext">${rule.min_hits===1?'단일 로그':`${rule.window_seconds}초 내 ${rule.min_hits}회 이상 · ${esc(rule.group_by)}`} · 활성 룰의 점수를 합산</p><div class="toolbar"><button data-action="edit" data-id="${rule.id}">수정</button><button data-action="toggle" data-id="${rule.id}">${rule.enabled?'비활성화':'활성화'}</button><button class="danger" data-action="delete" data-id="${rule.id}">삭제</button></div></article>`).join('')||'<p class="empty-state">등록된 룰이 없습니다. 에이전트를 선택해 첫 룰을 추가하세요.</p>';
}
async function reload(){
  const [hostData,ruleData]=await Promise.all([api('/api/hosts'),api('/api/rules')]);
  const selected=$('hostId').value,filter=$('hostFilter').value;
  const options=hostData.hosts.map(host=>`<option value="${host.id}">${esc(host.name)} · ${esc(host.ip)}${host.enabled?'':' (비활성)'}</option>`).join('');
  $('hostId').innerHTML='<option value="">에이전트 선택</option>'+options;$('hostFilter').innerHTML='<option value="">전체 에이전트</option>'+options;$('hostId').value=selected;$('hostFilter').value=filter;
  rules=ruleData.rules;render();status(hostData.hosts.length?`에이전트 ${hostData.hosts.length}개 · 룰 ${rules.length}개. 변경 사항은 다음 로그 조회에 반영됩니다.`:'에이전트 관리에서 호스트를 먼저 등록하세요.');
}
const safely=action=>async()=>{try{await action();}catch(error){status(error.message,true);}};
$('addCondition').onclick=()=>addCondition();$('resetRule').onclick=reset;$('hostFilter').onchange=render;$('reload').onclick=safely(reload);
$('ruleForm').onsubmit=async event=>{event.preventDefault();$('saveRule').disabled=true;try{await api(editing?'/api/rules/'+editing:'/api/rules',editing?'PATCH':'POST',payload());reset();await reload();status('룰을 저장했습니다. 상관분석에서 새로고침하면 탐지 결과를 볼 수 있습니다.');}catch(error){status(error.message,true);}finally{$('saveRule').disabled=false;}};
$('previewRule').onclick=safely(async()=>{if(!$('ruleForm').reportValidity())return;const result=await api('/api/rules/preview','POST',{rule:payload(),event_id:Number($('previewId').value)});$('previewResult').innerHTML=result.matched?SiemRisk.detectionHtml({detections:[result.detection],detection_score:result.detection.points}):`<b>불일치 · 0점</b><p>${esc(result.note)}</p>`;});
$('ruleList').onclick=async event=>{const button=event.target.closest('button[data-action]');if(!button)return;const rule=rules.find(r=>r.id===Number(button.dataset.id));if(!rule)return;try{if(button.dataset.action==='edit'){edit(rule);return;}if(button.dataset.action==='delete'){if(!confirm(`“${rule.name}” 룰을 삭제할까요? 기존 로그는 보존되며 해당 룰 점수는 다음 조회에서 제외됩니다.`))return;await api('/api/rules/'+rule.id,'DELETE');if(editing===rule.id)reset();}else{await api('/api/rules/'+rule.id,'PATCH',{enabled:!rule.enabled});if(editing===rule.id)$('enabled').checked=!rule.enabled;}await reload();}catch(error){status(error.message,true);}};
$('sshTemplate').onclick=()=>{const host=$('hostId').value;reset();$('hostId').value=host;$('ruleName').value='반복 SSH 인증 실패';$('attack').value='SSH 무차별 대입';$('points').value=120;$('minHits').value=5;$('windowSeconds').value=300;$('reason').value='같은 출발지에서 5분 내 인증 실패가 5회 이상 반복되어 암호 추측 시도 가능성이 높다고 판단합니다. 운영 점검이나 사용자 오입력 여부를 함께 확인하세요.';$('conditions').replaceChildren();addCondition({field:'event',operator:'equals',value:'AUTH_FAILURE'});addCondition({field:'message',operator:'contains',value:'failed password'});status('예시를 채웠습니다. 적용 에이전트와 실제 로그를 확인하고 저장하세요.');};
$('ruleForm').addEventListener('input',()=>{$('previewResult').textContent='입력이 변경되었습니다. 다시 테스트하세요.';});
reset();safely(reload)();
