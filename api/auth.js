import config from '../aleph.config.json' with { type: 'json' };

// 공개 키도 서버 함수에만 둡니다. 서버 전용 자료 키는 Auth 전달에 사용하지 않습니다.
const publishableKey = 'sb_publishable_9ohhX0Y5CQoKTfsNg7BsBQ_R0qaBGpb';

export function createAuthHandler({ env = process.env, fetchImpl = fetch } = {}) {
  return async function auth(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const fail = (status, error) => res.status(status).json({ error });
    const query = new URL(req.url, config.publicAppUrl).searchParams;
    const path = query.get('authPath');
    const method = req.method;
    const valid = (path === 'token' && method === 'POST'
        && ['password', 'refresh_token'].includes(query.get('grant_type')))
      || (path === 'logout' && method === 'POST' && query.get('scope') === 'local')
      || (path === 'user' && method === 'GET');
    const allowedQuery = path === 'token' ? ['authPath', 'grant_type']
      : path === 'logout' ? ['authPath', 'scope'] : ['authPath'];
    if (!valid || [...query.keys()].some(key => !allowedQuery.includes(key)
        || query.getAll(key).length !== 1)) {
      return fail(400, '허용되지 않은 인증 요청입니다.');
    }
    const projectUrl = new URL(config.identityProvider.issuer).origin;
    if (env.SUPABASE_URL !== projectUrl) return fail(503, '인증 연결을 준비 중입니다.');
    const headers = { apikey: publishableKey };
    if (path !== 'token') {
      const authorization = req.headers?.authorization;
      if (typeof authorization !== 'string'
          || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(authorization)) {
        return fail(401, '유효한 로그인이 필요합니다.');
      }
      headers.Authorization = authorization;
    }
    const version = req.headers?.['x-supabase-api-version'];
    if (typeof version === 'string' && /^\d{4}-\d{2}-\d{2}$/u.test(version)) {
      headers['X-Supabase-Api-Version'] = version;
    }
    let body;
    if (method === 'POST' && path === 'token') {
      try {
        const value = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
        if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error();
        const fields = query.get('grant_type') === 'password' ? ['email', 'password'] : ['refresh_token'];
        if (fields.some(key => typeof value[key] !== 'string' || !value[key])) throw new Error();
        body = JSON.stringify(value);
        if (Buffer.byteLength(body) > 16384) throw new Error();
        headers['Content-Type'] = 'application/json';
      } catch { return fail(400, '인증 입력을 확인해 주세요.'); }
    }
    const upstream = new URL(`/auth/v1/${path}`, projectUrl);
    for (const [key, value] of query) if (key !== 'authPath') upstream.searchParams.set(key, value);
    try {
      const response = await fetchImpl(upstream, { method, headers,
        ...(body === undefined ? {} : { body }), redirect: 'error',
        signal: AbortSignal.timeout(10000) });
      const responseVersion = response.headers.get('x-supabase-api-version');
      if (responseVersion && /^\d{4}-\d{2}-\d{2}$/u.test(responseVersion)) {
        res.setHeader('X-Supabase-Api-Version', responseVersion);
      }
      if (response.status === 204) return res.status(204).end();
      const data = await response.json();
      if (JSON.stringify(data).includes(publishableKey)) return fail(502, '인증 응답을 확인하지 못했습니다.');
      // SDK의 정상 세션·오류 응답만 전달하고 요청 본문·키·토큰을 기록하지 않습니다.
      return res.status(response.status).json(data);
    } catch { return fail(502, '인증 서버에 연결하지 못했습니다.'); }
  };
}

export default createAuthHandler();
