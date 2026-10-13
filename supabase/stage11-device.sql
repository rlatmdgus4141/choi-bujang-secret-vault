-- Learning app connection registrations only; existing notes, backups and audit are untouched.
CREATE SCHEMA vault_access;
REVOKE ALL ON SCHEMA vault_access FROM PUBLIC,anon,authenticated;
GRANT USAGE ON SCHEMA vault_access TO service_role;
CREATE TABLE vault_access.devices (
 id uuid PRIMARY KEY,owner_id uuid NOT NULL,public_key jsonb NOT NULL,
 approved boolean NOT NULL DEFAULT false,grant_nonce uuid NOT NULL UNIQUE,
 challenge text,challenge_expires_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL DEFAULT now()+interval '12 hours',created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE vault_access.request_nonces (
 device_id uuid NOT NULL REFERENCES vault_access.devices(id),nonce uuid NOT NULL,
 used_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(device_id,nonce)
);
ALTER TABLE vault_access.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_access.request_nonces ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON vault_access.devices,vault_access.request_nonces FROM PUBLIC,anon,authenticated,service_role;
GRANT SELECT,INSERT,UPDATE ON vault_access.devices TO service_role;
GRANT SELECT,INSERT ON vault_access.request_nonces TO service_role;
CREATE FUNCTION public.vault_device_register(p_id uuid,p_owner uuid,p_key jsonb,p_grant_nonce uuid,p_challenge text,p_deadline timestamptz)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
BEGIN
 IF current_user<>'service_role' OR p_owner IS NULL OR p_id IS NULL OR p_deadline<=now()
   OR p_deadline>now()+interval '3 minutes' OR p_key->>'kty'<>'EC' OR p_key->>'crv'<>'P-256'
   OR p_key ? 'd' OR p_challenge IS NULL THEN RAISE EXCEPTION 'device_request_forbidden'; END IF;
 INSERT INTO vault_access.devices(id,owner_id,public_key,grant_nonce,challenge,challenge_expires_at)
 VALUES(p_id,p_owner,p_key,p_grant_nonce,p_challenge,p_deadline);
 RETURN true;
END $$;
CREATE FUNCTION public.vault_device_confirm(p_id uuid,p_owner uuid,p_challenge text)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
BEGIN
 IF current_user<>'service_role' THEN RAISE EXCEPTION 'device_confirm_forbidden'; END IF;
 UPDATE vault_access.devices SET approved=true,challenge=NULL
 WHERE id=p_id AND owner_id=p_owner AND approved=false AND challenge=p_challenge AND challenge_expires_at>now();
 RETURN FOUND;
END $$;
CREATE FUNCTION public.vault_device_consume(p_id uuid,p_owner uuid,p_nonce uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
BEGIN
 IF current_user<>'service_role' THEN RAISE EXCEPTION 'device_request_forbidden'; END IF;
 PERFORM 1 FROM vault_access.devices WHERE id=p_id AND owner_id=p_owner AND approved=true AND expires_at>now() FOR SHARE;
 IF NOT FOUND OR p_nonce IS NULL THEN RETURN false; END IF;
 INSERT INTO vault_access.request_nonces(device_id,nonce) VALUES(p_id,p_nonce) ON CONFLICT DO NOTHING;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION public.vault_device_register(uuid,uuid,jsonb,uuid,text,timestamptz),
 public.vault_device_confirm(uuid,uuid,text),public.vault_device_consume(uuid,uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.vault_device_register(uuid,uuid,jsonb,uuid,text,timestamptz),
 public.vault_device_confirm(uuid,uuid,text),public.vault_device_consume(uuid,uuid,uuid) TO service_role;

-- Private tables stay outside exposed Data API schemas. Only server RPCs can read/revoke a registration.
CREATE FUNCTION public.vault_device_lookup(p_id uuid,p_owner uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
DECLARE row vault_access.devices%ROWTYPE;
BEGIN
 IF current_user<>'service_role' THEN RAISE EXCEPTION 'device_lookup_forbidden'; END IF;
 SELECT * INTO row FROM vault_access.devices WHERE id=p_id AND owner_id=p_owner;
 IF NOT FOUND THEN RETURN NULL; END IF;
 RETURN to_jsonb(row);
END $$;
CREATE FUNCTION public.vault_device_revoke(p_id uuid,p_owner uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path='' AS $$
BEGIN
 IF current_user<>'service_role' THEN RAISE EXCEPTION 'device_revoke_forbidden'; END IF;
 UPDATE vault_access.devices SET approved=false,challenge=NULL WHERE id=p_id AND owner_id=p_owner;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION public.vault_device_lookup(uuid,uuid),public.vault_device_revoke(uuid,uuid) FROM PUBLIC,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.vault_device_lookup(uuid,uuid),public.vault_device_revoke(uuid,uuid) TO service_role;
