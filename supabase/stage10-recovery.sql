-- Stage 10: private, immutable first snapshots; no existing permissions/policies are relaxed.
CREATE SCHEMA IF NOT EXISTS vault_recovery;
REVOKE ALL ON SCHEMA vault_recovery FROM PUBLIC, anon, authenticated;
GRANT USAGE ON SCHEMA vault_recovery TO service_role;

CREATE TABLE vault_recovery.note_backups (
  id uuid PRIMARY KEY, owner_id uuid NOT NULL, title text NOT NULL, content text NOT NULL,
  position integer NOT NULL, original_created_at timestamptz NOT NULL,
  content_hash text NOT NULL CHECK (content_hash ~ '^[a-f0-9]{64}$'),
  backup_version text NOT NULL DEFAULT 'stage10-v1', verified_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE vault_recovery.audit (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(), at timestamptz NOT NULL DEFAULT now(),
  action text NOT NULL CHECK (action IN ('snapshot', 'restore')),
  note_id uuid NOT NULL, owner_id uuid NOT NULL, content_hash text NOT NULL
);
ALTER TABLE vault_recovery.note_backups ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_recovery.audit ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON vault_recovery.note_backups, vault_recovery.audit FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT ON vault_recovery.note_backups TO service_role;
GRANT SELECT, INSERT ON vault_recovery.audit TO service_role;
-- No FK to live notes/auth.users: deletion must not erase backups or judge identities.

CREATE FUNCTION vault_recovery.note_hash(p_title text, p_content text)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path = '' AS $$
  SELECT encode(extensions.digest(convert_to(
    octet_length(convert_to(p_title, 'UTF8'))::text || ':' || p_title ||
    octet_length(convert_to(p_content, 'UTF8'))::text || ':' || p_content, 'UTF8'), 'sha256'), 'hex');
$$;
REVOKE ALL ON FUNCTION vault_recovery.note_hash(text,text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION vault_recovery.note_hash(text,text) TO service_role;

-- The narrow trigger needs definer privilege to create immutable backups. It is not an RPC.
CREATE FUNCTION vault_recovery.snapshot_new_note() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
DECLARE saved vault_recovery.note_backups%ROWTYPE; h text;
BEGIN
  IF TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME <> 'notes' OR TG_OP <> 'INSERT'
     OR NEW.owner_id IS NULL THEN RAISE EXCEPTION 'snapshot_invalid'; END IF;
  h := vault_recovery.note_hash(NEW.title, NEW.content);
  INSERT INTO vault_recovery.note_backups(id,owner_id,title,content,position,original_created_at,content_hash)
    VALUES (NEW.id,NEW.owner_id,NEW.title,NEW.content,NEW.position,NEW.created_at,h)
    ON CONFLICT (id) DO NOTHING;
  SELECT * INTO STRICT saved FROM vault_recovery.note_backups WHERE id=NEW.id;
  IF saved.owner_id <> NEW.owner_id OR saved.content_hash <> h
     OR saved.content_hash <> vault_recovery.note_hash(saved.title,saved.content) THEN
    RAISE EXCEPTION 'snapshot_conflict';
  END IF;
  INSERT INTO vault_recovery.audit(action,note_id,owner_id,content_hash)
    VALUES ('snapshot',NEW.id,NEW.owner_id,h);
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION vault_recovery.snapshot_new_note() FROM PUBLIC, anon, authenticated, service_role;

-- Capture the four current fake notes before any recovery drill. Never copy content to Git.
INSERT INTO vault_recovery.note_backups(id,owner_id,title,content,position,original_created_at,content_hash)
  SELECT id,owner_id,title,content,position,created_at,vault_recovery.note_hash(title,content)
  FROM public.notes WHERE owner_id IS NOT NULL;
INSERT INTO vault_recovery.audit(action,note_id,owner_id,content_hash)
  SELECT 'snapshot',id,owner_id,content_hash FROM vault_recovery.note_backups;
CREATE TRIGGER stage10_snapshot_on_insert AFTER INSERT ON public.notes
  FOR EACH ROW EXECUTE FUNCTION vault_recovery.snapshot_new_note();

-- Only the server service role can execute this transaction. The server supplies verified owner ID.
CREATE FUNCTION public.vault_restore_note(p_id uuid, p_owner uuid, p_dry_run boolean DEFAULT false)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path = '' AS $$
DECLARE saved vault_recovery.note_backups%ROWTYPE; live_owner uuid; restored_hash text;
BEGIN
  IF current_user <> 'service_role' OR p_id IS NULL OR p_owner IS NULL OR p_dry_run IS NULL THEN
    RAISE EXCEPTION 'restore_forbidden' USING ERRCODE='42501';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(p_id::text, 10));
  SELECT * INTO saved FROM vault_recovery.note_backups WHERE id=p_id AND owner_id=p_owner;
  IF NOT FOUND THEN RAISE EXCEPTION 'backup_not_found' USING ERRCODE='P0002'; END IF;
  IF saved.backup_version <> 'stage10-v1' OR saved.content_hash <>
     vault_recovery.note_hash(saved.title,saved.content) THEN
    RAISE EXCEPTION 'backup_invalid' USING ERRCODE='22000';
  END IF;
  SELECT owner_id INTO live_owner FROM public.notes WHERE id=p_id FOR UPDATE;
  IF FOUND AND live_owner IS DISTINCT FROM p_owner THEN
    RAISE EXCEPTION 'backup_not_found' USING ERRCODE='P0002';
  END IF;
  IF p_dry_run THEN
    RETURN jsonb_build_object('id',p_id,'owner_id',p_owner,'restored',false,
      'hash',saved.content_hash,'backupVersion',saved.backup_version);
  END IF;
  INSERT INTO public.notes(id,owner_id,title,content,position,created_at)
    VALUES(saved.id,saved.owner_id,saved.title,saved.content,saved.position,saved.original_created_at)
    ON CONFLICT(id) DO UPDATE SET title=EXCLUDED.title,content=EXCLUDED.content,
      position=EXCLUDED.position,created_at=EXCLUDED.created_at
    WHERE public.notes.owner_id=EXCLUDED.owner_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'restore_conflict'; END IF;
  SELECT vault_recovery.note_hash(title,content) INTO restored_hash FROM public.notes
    WHERE id=saved.id AND owner_id=saved.owner_id;
  IF restored_hash IS DISTINCT FROM saved.content_hash THEN RAISE EXCEPTION 'restore_invalid'; END IF;
  INSERT INTO vault_recovery.audit(action,note_id,owner_id,content_hash)
    VALUES('restore',saved.id,saved.owner_id,restored_hash);
  RETURN jsonb_build_object('id',saved.id,'owner_id',saved.owner_id,'restored',true,
    'hash',restored_hash,'backupVersion',saved.backup_version);
END;
$$;
REVOKE ALL ON FUNCTION public.vault_restore_note(uuid,uuid,boolean) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.vault_restore_note(uuid,uuid,boolean) TO service_role;
