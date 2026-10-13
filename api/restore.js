import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { UUID } from '../src/resources.mjs';
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
      if (!body || Array.isArray(body) || !UUID.test(body.id ?? '')
          || Object.keys(body).some(field => !['id', 'dryRun'].includes(field))
          || Object.hasOwn(body, 'dryRun') && typeof body.dryRun !== 'boolean') {
        return res.status(400).json({ error: '복구할 메모 ID와 선택적인 dryRun만 보내 주세요.' });
      }
      const { data, error } = await runtime.client.rpc('vault_restore_note', {
        p_id: body.id.toLowerCase(), p_owner: identity.userId, p_dry_run: body.dryRun === true,
      });
      if (error?.code === 'P0002') return res.status(404).json({ error: '복구할 사본을 찾을 수 없습니다.' });
      if (error?.code === '22000') return res.status(409).json({ error: '사본 검증에 실패했습니다.' });
      if (error || !data || data.id !== body.id.toLowerCase() || data.owner_id !== identity.userId
          || !/^[a-f0-9]{64}$/u.test(data.hash ?? '') || data.backupVersion !== 'stage10-v1'
          || data.restored !== (body.dryRun !== true)) throw new Error('restore_invalid');
      return res.status(200).json({ id: data.id, restored: data.restored,
        hash: data.hash, backupVersion: data.backupVersion });
    } catch { return res.status(502).json({ error: '복구를 완료할 수 없습니다.' }); }
  };
}
export default createRestoreHandler();
