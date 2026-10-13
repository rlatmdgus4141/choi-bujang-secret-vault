// Server-owned resource identifiers. No request role or resource selector changes these mappings.
export const RESOURCE_IDS = Object.freeze({ notes: 'notes.personal', notices: 'notices.instructor' });
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

export function apiResourcePath(req, resource, itemRoute) {
  const base = `/api/${resource}`;
  // Direct handler tests have no transport URL; production always supplies one.
  const raw = req.url ?? (itemRoute ? `${base}/${req.query?.id ?? ''}` : base);
  if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//')
      || /[%\\#]/u.test(raw)) return null;
  const [path, search = ''] = raw.split('?');
  const id = itemRoute ? path.slice(base.length + 1) : null;
  if (itemRoute ? !path.startsWith(`${base}/`) || !UUID.test(id) : path !== base) return null;
  const params = new URLSearchParams(search);
  // The only supported query value selects the same resource ID; no action/role/zone selectors.
  for (const [key, value] of params) {
    if (key !== 'id' || !itemRoute || value.toLowerCase() !== id.toLowerCase()) return null;
  }
  if (params.getAll('id').length > 1) return null;
  if (req.query?.id !== undefined && (typeof req.query.id !== 'string' || !itemRoute
      || req.query.id.toLowerCase() !== id.toLowerCase())) return null;
  return { resourceId: RESOURCE_IDS[resource], id: id?.toLowerCase() ?? null };
}
