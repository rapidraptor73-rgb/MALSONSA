(function(root){
  'use strict';
  const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  const names = {AUTH_FAILURE:'인증 실패',AUTH_SUCCESS:'인증 성공',PRIVILEGE_USE:'권한 사용',ACCOUNT_CHANGE:'계정 변경',FILE_TRANSFER:'파일 전송',REGISTRY_CHANGE:'레지스트리 변경',SCAN:'스캔',MALWARE:'악성코드',LOG:'일반 로그'};
  function priority(value){
    const score=Number(value);
    if(value===null || value===undefined || value==='' || !Number.isFinite(score) || score<0) return {key:'unknown',label:'미산정',action:'점수 확인'};
    if(score>=120) return {key:'critical',label:'CRITICAL',action:'최우선 검토'};
    if(score>=90) return {key:'high',label:'HIGH',action:'우선 검토'};
    if(score>=60) return {key:'medium',label:'MEDIUM',action:'연관성 검토'};
    return {key:'low',label:'LOW',action:'참고 로그'};
  }
  function scoreBadge(value){
    const p=priority(value);
    return `<span class="risk-badge risk-${p.key}">${p.label}<b>${p.key==='unknown'?'—':escape(value)+'점'}</b></span><span class="subtext priority-note">${p.action}</span>`;
  }
  function elapsed(anchor,candidate){
    const parse=v=>new Date(String(v||'').replace(/(\.\d{3})\d+(?=(?:Z|[+-]\d{2}:\d{2})?$)/,'$1')).getTime();
    const seconds=Math.round(Math.abs(parse(anchor.time||anchor.event_time)-parse(candidate.time||candidate.event_time))/1000);
    if(!Number.isFinite(seconds)) return '';
    return seconds<60 ? `${seconds}초 차이. ` : `${Math.floor(seconds/60)}분 ${seconds%60}초 차이. `;
  }
  function reasons(raw,anchor={},candidate={}){
    if(!Array.isArray(raw)) return [];
    return raw.map(item=>{
      const match=String(item).match(/^([^:]+):([+-]\d+)$/);
      const key=match?match[1]:String(item), points=match?Number(match[2]):null;
      const descriptions={
        same_src:['같은 출발지 IP',`두 로그의 SRC가 ${candidate.src_ip||anchor.src_ip||'동일 IP'}로 같습니다. 같은 출발지의 활동을 연결합니다.`],
        same_dst:['같은 목적지 IP',`두 로그의 DST가 ${candidate.dst_ip||anchor.dst_ip||'동일 IP'}로 같습니다. 같은 대상에 발생한 활동을 연결합니다.`],
        same_user:['동일 사용자',`두 로그에 ${candidate.user||anchor.user||'동일 계정'} 사용자가 기록되어 계정 기준으로 연관성을 더합니다.`],
        time_5m:['5분 이내 발생',elapsed(anchor,candidate)+'발생 시각이 5분 이내여서 시간상 가까운 활동으로 봅니다.'],
        time_15m:['15분 이내 발생',elapsed(anchor,candidate)+'발생 시각이 5분 초과·15분 이내여서 시간 연관성을 더합니다.'],
        time_30m:['30분 이내 발생',elapsed(anchor,candidate)+'발생 시각이 15분 초과·30분 이내여서 시간 연관성을 더합니다.'],
        attack_sequence:['연관된 공격 단계',`${names[anchor.event]||anchor.event||'앵커 이벤트'} ↔ ${names[candidate.event]||candidate.event||'비교 이벤트'}. 룰에 등록된 단계 조합입니다. 발생 순서의 증명을 뜻하지는 않습니다.`],
        same_mitre:['동일 MITRE 분류',`두 로그가 ${candidate.mitre||anchor.mitre||'동일 기법'}로 분류되어 기법 기준 연관성을 더합니다.`],
        suspicious:['의심 이벤트 유형',`${names[candidate.event]||candidate.event||'비교 이벤트'}는 현재 분류 룰의 의심 유형에 포함되어 추가 점수를 받습니다.`]
      };
      const [label,description]=descriptions[key]||['추가 규칙',`서버가 전달한 규칙: ${key}`];
      return {key,points,label,description};
    });
  }
  function reasonHtml(raw,anchor,candidate){
    const items=reasons(raw,anchor,candidate);
    if(!items.length) return '<span class="muted">산정 근거가 제공되지 않았습니다.</span>';
    const known=items.every(item=>item.points!==null),total=items.reduce((sum,item)=>sum+(item.points||0),0);
    const point=item=>item.points===null?'점수 미제공':`${item.points>=0?'+':''}${item.points}점`;
    return `<span class="reason-preview">${items.slice(0,2).map(item=>escape(item.label)+' '+point(item)).join(' · ')}${items.length>2?' 외 '+(items.length-2)+'개':''}</span><details class="reason-details"><summary>근거 ${items.length}개${known?' · 합계 '+total+'점':''} 자세히</summary><ol class="reason-list">${items.map(item=>`<li><div class="reason-heading"><span>${escape(item.label)}</span><span class="reason-points">${point(item)}</span></div><p>${escape(item.description)}</p></li>`).join('')}</ol></details>`;
  }
  function detectionHtml(event={}){
    const detections=event.detections||[];
    if(!detections.length) return '<span class="muted">일치 룰 없음 · 공격 안전 여부를 뜻하지 않습니다.</span>';
    return `<div class="detection-result">${scoreBadge(event.detection_score)}<span class="subtext">현재 룰 기준 · 추정 공격</span><details class="reason-details"><summary>${detections.map(item=>escape(item.attack)).join(' · ')} · 근거 ${detections.length}개</summary><ol class="reason-list">${detections.map(item=>`<li><div class="reason-heading"><span>${escape(item.name)} · ${escape(item.attack)} 의심</span><span class="reason-points">+${escape(item.points)}점</span></div><p>${escape(item.reason)}</p>${item.evidence.map(e=>`<p>${escape(e.field)} ${e.operator==='contains'?'포함':'일치'}: <code>${escape(e.expected)}</code><br>관찰값: ${escape(e.actual)}</p>`).join('')}${item.min_hits>1?`<p>${escape(item.window_seconds)}초 내 ${escape(item.hits)}회 관찰 / 기준 ${escape(item.min_hits)}회 · ${escape(item.group_by)}</p>`:''}</li>`).join('')}</ol></details></div>`;
  }
  function eventRiskHtml(event={}){
    const risk=event.risk_summary;
    if(!risk) return '<span class="risk-badge risk-unknown">미산정</span><span class="subtext">위험도 조회 필요</span>';
    const examples=(risk.examples||[]).map(item=>`<li>LOG ${escape(item.id)} · ${escape(names[item.event]||item.event)} · +${escape(item.score)}점</li>`).join('');
    return `<div class="event-risk">${scoreBadge(risk.total_score)}<span class="subtext">종합 검토 점수</span><span class="risk-self">로그 자체 ${escape(risk.self_score)}점 · ${priority(risk.self_score).label}</span><span class="subtext">연관 ${escape(risk.related_count)}건 · +${escape(risk.related_score)}점</span><details class="reason-details"><summary>합계 산정 보기</summary><div class="risk-breakdown"><p>자체 ${escape(risk.self_score)}점 = 의심 유형 ${escape(risk.type_score)}점 + 일치 룰 ${escape(risk.rule_score)}점</p><p>종합 ${escape(risk.total_score)}점 = 자체 ${escape(risk.self_score)}점 + 연관 상관점수 합계 ${escape(risk.related_score)}점</p><p>같은 호스트 · SRC 또는 사용자 일치 · 전후 ${escape(risk.minutes)}분 · 상관점수 ${escape(risk.min_score)}점 이상. 두 로그 중 하나는 의심 이벤트 유형이어야 합니다.</p>${!risk.time_valid?'<p>시간 형식 오류: 연관 점수를 계산하지 않았습니다.</p>':''}<p>최근 ${escape(risk.candidate_count)}건(최대 ${escape(risk.candidate_limit)}건)에서 높은 점수순 최대 ${escape(risk.related_limit)}건을 합산합니다.${risk.matched_count>risk.related_count?' 합산 상한에 도달했습니다.':''} 반복 로그가 많으면 합계가 커집니다. 공격 확률이나 침해 확정을 뜻하지 않습니다.</p>${examples?`<b>높은 점수의 연관 로그 예시</b><ul>${examples}</ul>`:''}</div></details></div>`;
  }
  const api={priority,scoreBadge,reasons,reasonHtml,detectionHtml,eventRiskHtml};
  if(typeof module==='object' && module.exports) module.exports=api; else root.SiemRisk=api;
})(typeof window!=='undefined'?window:globalThis);
