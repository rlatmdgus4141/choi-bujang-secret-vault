export const publicProbes = Object.freeze([
  {id:'public_metadata',stage:'12',name:'작전실 공개 메타데이터',method:'GET',path:'/api/operations',expected:200},
  {id:'anonymous_notes',stage:'1–3',name:'무인증 메모 조회',method:'GET',path:'/api/notes',expected:401},
  {id:'anonymous_restore',stage:'10',name:'무인증 복구 요청',method:'POST',path:'/api/restore',expected:401},
  {id:'anonymous_device',stage:'6·11',name:'무인증 기기 조회',method:'GET',path:'/api/device',expected:401},
  {id:'anonymous_notice',stage:'8',name:'무인증 공지 조회',method:'GET',path:'/api/notices',expected:401},
  {id:'metadata_write',stage:'12',name:'작전실 메타데이터 변경 거부',method:'PUT',path:'/api/operations',expected:405}
]);
export const unexecutedCoverage = Object.freeze([
  {stage:'3–5',name:'A/B 타인 메모 접근·원본 DB 권한',expected:'본인 허용 / 타인·직접 접근 거부'},
  {stage:'6–7',name:'운영 엔진 미등록 기기·추가 확인',expected:'미등록 거부 / 추가 확인 후 정상 허용'},
  {stage:'8',name:'운영 엔진 구역 밖 조회',expected:'구역 밖 거부 / 허용 구역 정상'},
  {stage:'9',name:'운영 탐지·신원 회수·재접속',expected:'복합 이상만 제안 / 회수 후 거부 / 정상 기기 유지'},
  {stage:'10',name:'학습 DB 변조·삭제 후 실제 복구',expected:'한 건 일치 / 다른 자료·감사 보존'},
  {stage:'11',name:'운영 엔진 경로·본문 서명 변조',expected:'무서명·변조 거부 / 정상 서명 허용'}
]);
export function observation(probe,response) {
  const requestId=response.headers.get('x-vault-request-id');
  const checkedAt=response.headers.get('x-vault-checked-at');
  const evidence=typeof requestId==='string' && /^[a-f0-9-]{36}$/.test(requestId)
    && typeof checkedAt==='string' && Number.isFinite(Date.parse(checkedAt));
  return {id:probe.id,stage:probe.stage,name:probe.name,method:probe.method,path:probe.path,
    scope:'live_api',expected:probe.expected,actual:response.status,
    requestId:evidence?requestId:null,checkedAt:evidence?checkedAt:null,
    status:!evidence?'evidence_missing':response.status===probe.expected?'passed':'failed'};
}
