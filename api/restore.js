import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { UUID } from '../src/resources.mjs';
import { noteContentHash } from '../src/note-integrity.mjs';
import config from '../aleph.config.json' with { type: 'json' };

export function createRestoreHandler({ clientFactory = createClient, env = process.env } = {}) {
  let runtime;
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Vary', 'Authorization');
    if (typeof req.headers?.authorization !== 'string' || !req.headers.authorization) {
      return res.status(401).json({ error: '유효한 로그인이 필요합니다.' });
    }
    const url = env.SUPABASE_URL, key = env.SUPABASE_SECRET_KEY;
    if (url !== new URL(config.identityProvider.issuer).origin || !key?.startsWith('sb_secret_')) {
      return res.status(503).json({ error: '서버 자료 연결을 준비 중입니다.' });
    }
    try {
      if (!runtime) {
        const client = clientFactory(url, key, { auth: { persistSession: false,
          autoRefreshToken: false, detectSessionInUrl: false },
          global: { fetch: (input, init) => fetch(input, { ...init, signal: AbortSignal.timeout(10000) }) } });
        runtime = { client, verify: createLoginVerifier({ config, supabaseClient: client }) };
      }
      const identity = await runtime.verify(req.headers.authorization);
      if (!identity?.userId) return res.status(401).json({ error: '유효한 로그인이 필요합니다.' });
      if (req.method !== 'POST') {
        res.setHeader('Allow', 'POST');
        return res.status(405).json({ error: '허용되지 않은 요청입니다.' });
      }
      if (req.url && req.url !== '/api/restore' || Object.keys(req.query ?? {}).length) {
        return res.status(400).json({ error: '허용되지 않은 복구 경로입니다.' });
      }
      let body;
      try { body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
      catch { return res.status(400).json({ error: '올바른 JSON을 보내 주세요.' }); }
      if (!body || Array.isArray(body) || typeof body.id !== 'string' || !UUID.test(body.id)
          || Object.keys(body).some(field => !['id', 'dryRun'].includes(field))
          || Object.hasOwn(body, 'dryRun') && typeof body.dryRun !== 'boolean') {
        return res.status(400).json({ error: '복구할 메모 ID와 선택적인 dryRun만 보내 주세요.' });
      }
      const args = { p_id: body.id.toLowerCase(), p_owner: identity.userId };
      const valid = (data, restored) => data && data.id === args.p_id && data.owner_id === identity.userId
        && /^[a-f0-9]{64}$/u.test(data.hash ?? '') && data.backupVersion === 'stage10-v1'
        && data.restored === restored;
      // Read the private verified snapshot first; do not accept a merely well-formed response hash.
      const { data: snapshot, error: snapshotError } = await runtime.client.rpc('vault_restore_note', {
        ...args, p_dry_run: true,
      });
      if (snapshotError?.code === 'P0002') return res.status(404).json({ error: '복구할 사본을 찾을 수 없습니다.' });
      if (snapshotError?.code === '22000') return res.status(409).json({ error: '사본 검증에 실패했습니다.' });
      if (snapshotError || !valid(snapshot, false)) throw new Error('snapshot_invalid');
      const result = data => ({ id: data.id, owner_id: data.owner_id, restored: data.restored,
        hash: data.hash, backupVersion: data.backupVersion });
      if (body.dryRun === true) return res.status(200).json(result(snapshot));
      const { data, error } = await runtime.client.rpc('vault_restore_note', {
        ...args, p_dry_run: false,
      });
      if (error?.code === 'P0002') return res.status(404).json({ error: '복구할 사본을 찾을 수 없습니다.' });
      if (error?.code === '22000') return res.status(409).json({ error: '사본 검증에 실패했습니다.' });
      if (error || !valid(data, true)) throw new Error('restore_invalid');
      const { data: row, error: readError } = await runtime.client.from('notes')
        .select('id,owner_id,title,content').eq('id', args.p_id).eq('owner_id', identity.userId).maybeSingle();
      if (readError) throw new Error('restored_read_failed');
      if (data.hash !== snapshot.hash || data.backupVersion !== snapshot.backupVersion
          || !row || row.id !== snapshot.id || row.owner_id !== snapshot.owner_id
          || noteContentHash(row.title, row.content) !== snapshot.hash) {
        return res.status(409).json({ error: '복구한 메모가 검증 사본과 일치하지 않습니다.' });
      }
      return res.status(200).json(result(data));
    } catch { return res.status(502).json({ error: '복구를 완료할 수 없습니다.' }); }
  };
}
export default createRestoreHandler();
