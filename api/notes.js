import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };

// 2단계 학습용 공개 API. 사용자 인증과 소유자 검사는 다음 단계에서 추가합니다.
export function createNotesHandler({ clientFactory = createClient, env = process.env } = {}) {
  return async function notes(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'GET') {
      res.setHeader('Allow', 'GET');
      return res.status(405).json({ error: '허용되지 않은 요청입니다.' });
    }
    const url = env.SUPABASE_URL;
    const key = env.SUPABASE_SECRET_KEY;
    if (!url || !key || !key.startsWith('sb_secret_')) {
      return res.status(503).json({ error: '서버 자료 연결을 준비 중입니다.' });
    }
    try {
      const client = clientFactory(url, key, {
        auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
        global: { fetch: (input, init) => fetch(input, {
          ...init, signal: AbortSignal.timeout(10000),
        }) },
      });
      const { data, error } = await client.from('notes')
        .select('id,title,content').order('position', { ascending: true });
      if (error || !Array.isArray(data)) throw new Error('Database read failed');
      // DB 응답·오류 전체를 반환하거나 기록하지 않습니다.
      return res.status(200).json({
        sampleMarker: config.sampleMarker,
        notes: data.map(({ id, title, content }) => ({ id, title, content })),
      });
    } catch {
      return res.status(502).json({ error: '자료를 불러올 수 없습니다.' });
    }
  };
}

export default createNotesHandler();
