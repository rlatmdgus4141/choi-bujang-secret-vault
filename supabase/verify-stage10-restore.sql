-- B's fictional note only. Run as postgres in the learning project's SQL Editor.
-- The drill and all appended audit rows are rolled back; no note content is printed.
BEGIN;
SELECT set_config('vault_drill.id',n.id::text,true),set_config('vault_drill.owner',n.owner_id::text,true)
FROM public.notes n JOIN auth.users u ON u.id=n.owner_id WHERE u.email='b@example.com';
SET LOCAL ROLE service_role;
DO $$
DECLARE target uuid:=current_setting('vault_drill.id')::uuid;
  owner uuid:=current_setting('vault_drill.owner')::uuid;
  saved vault_recovery.note_backups%ROWTYPE; reply jsonb; preview jsonb;
  other_before text; audit_before text; old_audit uuid[];
  phase text; checks jsonb:='[]'::jsonb; row_hash text; row_owner uuid; row_id uuid;
BEGIN
  SELECT * INTO STRICT saved FROM vault_recovery.note_backups WHERE id=target AND owner_id=owner;
  SELECT md5(coalesce(jsonb_agg(to_jsonb(n) ORDER BY n.id)::text,'')) INTO other_before FROM public.notes n WHERE id<>target;
  SELECT array_agg(event_id),md5(coalesce(jsonb_agg(to_jsonb(a) ORDER BY event_id)::text,''))
    INTO old_audit,audit_before FROM vault_recovery.audit a;
  FOREACH phase IN ARRAY ARRAY['modified','deleted'] LOOP
    IF phase='modified' THEN
      UPDATE public.notes SET title='temporary fake corruption',content='fictional drill' WHERE id=target AND owner_id=owner;
    ELSE DELETE FROM public.notes WHERE id=target AND owner_id=owner; END IF;
    preview:=public.vault_restore_note(target,owner,true);
    reply:=public.vault_restore_note(target,owner,false);
    SELECT id,owner_id,vault_recovery.note_hash(title,content) INTO STRICT row_id,row_owner,row_hash
      FROM public.notes WHERE id=target AND owner_id=owner;
    checks:=checks||jsonb_build_array(jsonb_build_object('phase',phase,
      'id_matches',row_id=saved.id AND reply->>'id'=saved.id::text,
      'owner_matches',row_owner=saved.owner_id AND reply->>'owner_id'=saved.owner_id::text,
      'content_hash_matches',row_hash=saved.content_hash AND reply->>'hash'=saved.content_hash AND preview->>'hash'=saved.content_hash,
      'others_preserved',other_before=(SELECT md5(coalesce(jsonb_agg(to_jsonb(n) ORDER BY n.id)::text,'')) FROM public.notes n WHERE id<>target),
      'old_audit_preserved',audit_before=(SELECT md5(coalesce(jsonb_agg(to_jsonb(a) ORDER BY event_id)::text,'')) FROM vault_recovery.audit a WHERE event_id=ANY(old_audit))));
  END LOOP;
  PERFORM set_config('vault_drill.checks',checks::text,true);
END $$;
SELECT current_setting('vault_drill.checks')::jsonb AS restore_checks;
ROLLBACK;
