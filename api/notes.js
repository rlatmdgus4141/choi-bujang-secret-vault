import { createClient } from '@supabase/supabase-js';
import { randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';
import config from '../aleph.config.json' with { type: 'json' };

// 기존 로그인 검증 도우미를 그대로 사용합니다. 소유자 검사는 4단계 과제입니다.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const publicNote = ({ id, title, content }) => ({ id, title, body: content });

export function createNotesHandler({ clientFactory = createClient, env = process.env, itemRoute = false } = {}) {
  let runtime;
  return async function notes(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Vary', 'Authorization');
    const authorization = req.headers?.authorization;
    if (typeof authorization !== 'string' || !authorization) {
      return res.status(401).json({ error: '유효한 로그인이 필요합니다.' });
    }
    const url = env.SUPABASE_URL;
    const key = env.SUPABASE_SECRET_KEY;
    if (!url || !key || !key.startsWith('sb_secret_')
        || url !== new URL(config.identityProvider.issuer).origin) {
      return res.status(503).json({ error: '서버 자료 연결을 준비 중입니다.' });
    }
    try {
      if (!runtime) {
        const client = clientFactory(url, key, {
          auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
          global: { fetch: (input, init) => fetch(input, {
            ...init, signal: AbortSignal.timeout(10000),
          }) },
        });
        runtime = { client, verifyLogin: createLoginVerifier({ config, supabaseClient: client }) };
      }
      const identity = await runtime.verifyLogin(authorization);
      if (!identity?.userId) {
        return res.status(401).json({ error: '유효한 로그인이 필요합니다.' });
      }
      const methods = itemRoute ? ['GET', 'PUT', 'DELETE'] : ['GET', 'POST'];
      if (!methods.includes(req.method)) {
        res.setHeader('Allow', methods.join(', '));
        return res.status(405).json({ error: '허용되지 않은 요청입니다.' });
      }
      let id;
      if (itemRoute) {
        id = req.query?.id ?? new URL(req.url, config.publicAppUrl).pathname.split('/').at(-1);
        if (typeof id !== 'string' || !UUID.test(id)) {
          return res.status(400).json({ error: '메모 ID는 UUID여야 합니다.' });
        }
        id = id.toLowerCase();
      }
      let input;
      if (['POST', 'PUT'].includes(req.method)) {
        try { input = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
        catch { return res.status(400).json({ error: '올바른 JSON을 보내 주세요.' }); }
        if (!input || Array.isArray(input) || typeof input.title !== 'string'
            || !input.title.trim() || input.title.length > 200
            || typeof input.body !== 'string' || input.body.length > 20000) {
          return res.status(400).json({ error: '제목은 1~200자, 본문은 20,000자 이내로 입력해 주세요.' });
        }
      }
      const db = runtime.client;
      if (!itemRoute && req.method === 'GET') {
        const { data, error } = await db.from('notes').select('id,title,content')
          .eq('owner_id', identity.userId).order('position', { ascending: true });
        if (error || !Array.isArray(data)) throw new Error('Database read failed');
        return res.status(200).json(data.map(publicNote));
      }
      if (req.method === 'POST') {
        id = input.id === undefined ? randomUUID() : input.id;
        if (typeof id !== 'string' || !UUID.test(id)) {
          return res.status(400).json({ error: '메모 ID는 UUID여야 합니다.' });
        }
        const { data, error } = await db.from('notes').insert({ id: id.toLowerCase(),
          title: input.title.trim(), content: input.body, owner_id: identity.userId })
          .select('id').single();
        if (error?.code === '23505') return res.status(409).json({ error: '이미 존재하는 메모 ID입니다.' });
        if (error || !data) throw new Error('Database write failed');
        return res.status(201).json({ id: data.id });
      }
      // 3단계의 의도된 남은 허점: 개별 메모는 신원만 확인하며 소유자 비교는 4단계에서 추가합니다.
      let result;
      if (req.method === 'GET') {
        result = await db.from('notes').select('id,title,content').eq('id', id).maybeSingle();
      } else if (req.method === 'PUT') {
        result = await db.from('notes').update({ title: input.title.trim(), content: input.body })
          .eq('id', id).select('id,title,content').maybeSingle();
      } else {
        result = await db.from('notes').delete().eq('id', id).select('id').maybeSingle();
      }
      if (result.error) throw new Error('Database operation failed');
      if (!result.data) return res.status(404).json({ error: '메모를 찾을 수 없습니다.' });
      return res.status(200).json(req.method === 'DELETE' ? { id: result.data.id } : publicNote(result.data));
    } catch {
      return res.status(502).json({ error: '자료를 불러올 수 없습니다.' });
    }
  };
}

export default createNotesHandler();
