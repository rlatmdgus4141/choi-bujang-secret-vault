import { attachEvidence } from '../src/request-evidence.mjs';
import { verifyDeviceRequest } from '../src/device-access.mjs';
import { createClient } from '@supabase/supabase-js';
import { randomUUID } from 'node:crypto';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { apiResourcePath, RESOURCE_IDS, UUID } from '../src/resources.mjs';
import config from '../aleph.config.json' with { type: 'json' };

export function createNoticesHandler({ clientFactory = createClient, env = process.env, itemRoute = false, deviceVerifier = verifyDeviceRequest } = {}) {
  let runtime;
  return async (req, res) => {
    attachEvidence(req, res, env);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Vary', 'Authorization');
    res.setHeader('X-Resource-Id', RESOURCE_IDS.notices);
    if (!req.headers?.authorization) return res.status(401).json({ error: 'login_required' });
    const url = env.SUPABASE_URL, key = env.SUPABASE_SECRET_KEY;
    if (url !== new URL(config.identityProvider.issuer).origin || !key?.startsWith('sb_secret_')) {
      return res.status(503).json({ error: 'service_unavailable' });
    }
    try {
      if (!runtime) {
        const client = clientFactory(url, key, {
          auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
          global: { fetch: (input, init) => fetch(input, { ...init, signal: AbortSignal.timeout(10000) }) },
        });
        runtime = { client, verifyLogin: createLoginVerifier({ config, supabaseClient: client }) };
      }
      const identity = await runtime.verifyLogin(req.headers.authorization);
      if (!identity?.userId) return res.status(401).json({ error: 'login_required' });
      if (config.step >= 11 && !await deviceVerifier(req, identity, runtime.client)) {
        return res.status(403).json({ error: '서버가 승인한 기기의 서명이 필요합니다.', code: 'device_not_approved' });
      }
      const methods = itemRoute ? ['GET', 'PUT'] : ['GET', 'POST'];
      if (!methods.includes(req.method)) {
        res.setHeader('Allow', methods.join(', '));
        return res.status(405).json({ error: 'method_not_allowed' });
      }
      const target = apiResourcePath(req, 'notices', itemRoute);
      if (!target) return res.status(400).json({ error: 'invalid_resource_path' });
      const db = runtime.client;
      if (req.method !== 'GET') {
        // Fresh server-side authority lookup, never body.role, user_metadata or a stale role claim.
        if (identity.kind !== 'student') return res.status(403).json({ error: 'instructor_required' });
        const { data, error } = await db.auth.admin.getUserById(identity.userId);
        if (error) return res.status(503).json({ error: 'authority_unavailable' });
        if (data?.user?.id !== identity.userId || data.user.app_metadata?.vault_role !== 'instructor') {
          return res.status(403).json({ error: 'instructor_required' });
        }
      }
      const fields = 'id,title,content';
      const publicNotice = row => ({ id: row.id, title: row.title, body: row.content });
      if (req.method === 'GET') {
        const query = db.from('notices').select(fields);
        const result = itemRoute ? await query.eq('id', target.id).maybeSingle()
          : await query.order('updated_at', { ascending: false });
        if (result.error) throw new Error('read failed');
        if (itemRoute && !result.data) return res.status(404).json({ error: 'resource_not_found' });
        return res.status(200).json(itemRoute ? publicNotice(result.data) : result.data.map(publicNotice));
      }
      let input;
      try { input = typeof req.body === 'string' ? JSON.parse(req.body) : req.body; }
      catch { return res.status(400).json({ error: 'invalid_json' }); }
      if (!input || Array.isArray(input) || typeof input.title !== 'string' || !input.title.trim()
          || input.title.length > 200 || typeof input.body !== 'string' || input.body.length > 20000) {
        return res.status(400).json({ error: 'invalid_content' });
      }
      const values = { title: input.title.trim(), content: input.body,
        updated_by: identity.userId, updated_at: new Date().toISOString() };
      const id = itemRoute ? target.id : input.id ?? randomUUID();
      if (typeof id !== 'string' || !UUID.test(id)) return res.status(400).json({ error: 'invalid_id' });
      const result = itemRoute
        ? await db.from('notices').update(values).eq('id', id).select(fields).maybeSingle()
        : await db.from('notices').insert({ ...values, id: id.toLowerCase() }).select(fields).single();
      if (result.error?.code === '23505') return res.status(409).json({ error: 'resource_exists' });
      if (result.error) throw new Error('write failed');
      if (!result.data) return res.status(404).json({ error: 'resource_not_found' });
      return res.status(itemRoute ? 200 : 201).json(publicNotice(result.data));
    } catch {
      return res.status(502).json({ error: 'service_unavailable' });
    }
  };
}
export default createNoticesHandler();
