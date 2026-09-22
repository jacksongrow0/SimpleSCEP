-- SimpleSCEP open-source baseline. Apply only to an empty PostgreSQL database.
-- Legacy hosted-service schemas are intentionally absent.

--
-- PostgreSQL database dump
--


-- Dumped from database version 17.11
-- Dumped by pg_dump version 17.11

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: app_current_uuid(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.app_current_uuid(name text) RETURNS uuid
    LANGUAGE sql STABLE
    AS $$
    SELECT NULLIF(current_setting(name, true), '')::UUID
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: acme_account; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.acme_account (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    acme_endpoint_id uuid NOT NULL,
    jwk_thumbprint text NOT NULL,
    jwk_json text NOT NULL,
    status character varying(16) DEFAULT 'valid'::character varying NOT NULL,
    contact text DEFAULT ''::text NOT NULL,
    eab_credential_id uuid,
    identifier_pin text DEFAULT ''::text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT acme_account_status_check CHECK (((status)::text = ANY ((ARRAY['valid'::character varying, 'deactivated'::character varying, 'revoked'::character varying])::text[])))
);

ALTER TABLE ONLY public.acme_account FORCE ROW LEVEL SECURITY;


--
-- Name: acme_authorization; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.acme_authorization (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    acme_order_id uuid NOT NULL,
    identifier_type character varying(8) NOT NULL,
    identifier_value text NOT NULL,
    status character varying(16) DEFAULT 'valid'::character varying NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    validated_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT acme_authorization_identifier_type_check CHECK (((identifier_type)::text = ANY ((ARRAY['dns'::character varying, 'ip'::character varying])::text[]))),
    CONSTRAINT acme_authorization_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'valid'::character varying, 'invalid'::character varying, 'deactivated'::character varying, 'expired'::character varying, 'revoked'::character varying])::text[])))
);

ALTER TABLE ONLY public.acme_authorization FORCE ROW LEVEL SECURITY;


--
-- Name: acme_challenge; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.acme_challenge (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    acme_authorization_id uuid NOT NULL,
    type character varying(48) NOT NULL,
    token text NOT NULL,
    status character varying(16) DEFAULT 'valid'::character varying NOT NULL,
    validated_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT acme_challenge_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'processing'::character varying, 'valid'::character varying, 'invalid'::character varying])::text[])))
);

ALTER TABLE ONLY public.acme_challenge FORCE ROW LEVEL SECURITY;


--
-- Name: acme_eab_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.acme_eab_credential (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    acme_endpoint_id uuid NOT NULL,
    label character varying(64) DEFAULT ''::character varying NOT NULL,
    kid text NOT NULL,
    mac_key_ciphertext bytea NOT NULL,
    identifier_pin text DEFAULT ''::text NOT NULL,
    single_use boolean DEFAULT false NOT NULL,
    expires_at timestamp without time zone,
    used_at timestamp without time zone,
    revoked_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.acme_eab_credential FORCE ROW LEVEL SECURITY;


--
-- Name: acme_endpoint; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.acme_endpoint (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    certificate_authority_id uuid NOT NULL,
    name character varying(64) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    validity_days integer DEFAULT 90 NOT NULL,
    allowed_ekus text DEFAULT 'server_auth'::text NOT NULL,
    subject_pattern text DEFAULT ''::text NOT NULL,
    san_pattern text DEFAULT ''::text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT acme_endpoint_name_not_blank CHECK ((btrim((name)::text) <> ''::text)),
    CONSTRAINT acme_endpoint_validity_days_check CHECK (((validity_days >= 1) AND (validity_days <= 3650)))
);

ALTER TABLE ONLY public.acme_endpoint FORCE ROW LEVEL SECURITY;


--
-- Name: acme_nonce; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.acme_nonce (
    value bytea NOT NULL,
    organization_id uuid NOT NULL,
    acme_endpoint_id uuid NOT NULL,
    issued_at timestamp without time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.acme_nonce FORCE ROW LEVEL SECURITY;


--
-- Name: acme_order; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.acme_order (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    acme_endpoint_id uuid NOT NULL,
    acme_account_id uuid NOT NULL,
    status character varying(16) DEFAULT 'pending'::character varying NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    not_before timestamp without time zone,
    not_after timestamp without time zone,
    certificate_id uuid,
    error_type text DEFAULT ''::text NOT NULL,
    error_detail text DEFAULT ''::text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT acme_order_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'ready'::character varying, 'processing'::character varying, 'valid'::character varying, 'invalid'::character varying])::text[])))
);

ALTER TABLE ONLY public.acme_order FORCE ROW LEVEL SECURITY;


--
-- Name: audit_event; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_event (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    actor_user_id uuid,
    actor_email text DEFAULT ''::text NOT NULL,
    action character varying(64) NOT NULL,
    target text DEFAULT ''::text NOT NULL,
    detail text DEFAULT ''::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    actor_ip text DEFAULT ''::text NOT NULL,
    actor_user_agent text DEFAULT ''::text NOT NULL,
    actor_session_id text DEFAULT ''::text NOT NULL
);

ALTER TABLE ONLY public.audit_event FORCE ROW LEVEL SECURITY;


--
-- Name: ca_import_job; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ca_import_job (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    created_by uuid,
    ca_name character varying(255) NOT NULL,
    ca_type character varying(32) NOT NULL,
    algorithm character varying(64) NOT NULL,
    certificate_pem text NOT NULL,
    chain_pem text DEFAULT ''::text NOT NULL,
    kms_import_job text NOT NULL,
    kms_crypto_key text NOT NULL,
    kms_key_version text DEFAULT ''::text NOT NULL,
    wrapping_method character varying(64) DEFAULT ''::character varying NOT NULL,
    wrapping_public_key_pem text DEFAULT ''::text NOT NULL,
    state character varying(32) DEFAULT 'preparing'::character varying NOT NULL,
    failure_reason text DEFAULT ''::text NOT NULL,
    certificate_authority_id uuid,
    expires_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    cancelled_by uuid,
    CONSTRAINT ca_import_job_ca_type_check CHECK (((ca_type)::text = ANY ((ARRAY['root'::character varying, 'issuing'::character varying])::text[]))),
    CONSTRAINT ca_import_job_state_check CHECK (((state)::text = ANY ((ARRAY['preparing'::character varying, 'ready_to_wrap'::character varying, 'importing'::character varying, 'completed'::character varying, 'failed'::character varying, 'expired'::character varying, 'cancelled'::character varying])::text[])))
);

ALTER TABLE ONLY public.ca_import_job FORCE ROW LEVEL SECURITY;


--
-- Name: certificate; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certificate (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    certificate_authority_id uuid NOT NULL,
    serial text NOT NULL,
    subject text NOT NULL,
    sans text DEFAULT ''::text NOT NULL,
    status character varying(32) DEFAULT 'issued'::character varying NOT NULL,
    csr_digest text NOT NULL,
    certificate_pem text NOT NULL,
    chain_pem text NOT NULL,
    issued_at timestamp without time zone DEFAULT now() NOT NULL,
    revoked_at timestamp without time zone,
    expires_at timestamp without time zone NOT NULL,
    profile character varying(16) DEFAULT 'csr'::character varying NOT NULL,
    ekus text DEFAULT ''::text NOT NULL,
    expiry_notified_at timestamp with time zone,
    CONSTRAINT certificate_profile_check CHECK (((profile)::text = ANY ((ARRAY['server'::character varying, 'client'::character varying, 'csr'::character varying, 'scep'::character varying, 'acme'::character varying, 'est'::character varying, 'infrastructure'::character varying])::text[]))),
    CONSTRAINT certificate_status_check CHECK (((status)::text = ANY ((ARRAY['issued'::character varying, 'revoked'::character varying, 'expired'::character varying])::text[])))
);

ALTER TABLE ONLY public.certificate FORCE ROW LEVEL SECURITY;


--
-- Name: certificate_authority; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certificate_authority (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    parent_id uuid,
    name character varying(255) NOT NULL,
    type character varying(32) NOT NULL,
    status character varying(32) DEFAULT 'active'::character varying NOT NULL,
    subject text NOT NULL,
    algorithm character varying(64) NOT NULL,
    kms_key_version text NOT NULL,
    certificate_pem text NOT NULL,
    chain_pem text NOT NULL,
    export_posture character varying(64) DEFAULT 'non_exportable_hsm'::character varying NOT NULL,
    not_before timestamp without time zone NOT NULL,
    not_after timestamp without time zone NOT NULL,
    issued_count bigint DEFAULT 0 NOT NULL,
    last_signed_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    issuance_ekus text DEFAULT 'client_auth'::text NOT NULL,
    deleted_at timestamp without time zone,
    CONSTRAINT certificate_authority_export_posture_check CHECK (((export_posture)::text = ANY ((ARRAY['non_exportable_hsm'::character varying, 'imported_hsm'::character varying, 'non_exportable_software'::character varying, 'imported_software'::character varying])::text[]))),
    CONSTRAINT certificate_authority_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'inactive'::character varying, 'retired'::character varying, 'deleted'::character varying])::text[]))),
    CONSTRAINT certificate_authority_type_check CHECK (((type)::text = ANY ((ARRAY['root'::character varying, 'issuing'::character varying])::text[])))
);

ALTER TABLE ONLY public.certificate_authority FORCE ROW LEVEL SECURITY;


--
-- Name: certificate_revocation; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certificate_revocation (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    certificate_id uuid NOT NULL,
    reason character varying(64) NOT NULL,
    revoked_at timestamp without time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.certificate_revocation FORCE ROW LEVEL SECURITY;


--
-- Name: certificate_signing_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.certificate_signing_audit (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    certificate_authority_id uuid NOT NULL,
    requester_user_id uuid,
    kms_key_version text NOT NULL,
    csr_digest text NOT NULL,
    certificate_serial text NOT NULL,
    purpose character varying(64) NOT NULL,
    signed_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.certificate_signing_audit FORCE ROW LEVEL SECURITY;


--
-- Name: crl_publication; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.crl_publication (
    organization_id uuid NOT NULL,
    certificate_authority_id uuid NOT NULL,
    crl_der bytea DEFAULT '\x'::bytea NOT NULL,
    crl_number bigint DEFAULT 0 NOT NULL,
    this_update timestamp without time zone,
    next_update timestamp without time zone,
    published_at timestamp without time zone,
    last_attempt_at timestamp without time zone,
    last_error text DEFAULT ''::text NOT NULL
);

ALTER TABLE ONLY public.crl_publication FORCE ROW LEVEL SECURITY;


--
-- Name: email_invitation; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_invitation (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    email character varying(255) NOT NULL,
    role character varying(64) DEFAULT 'administrator'::character varying NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    accepted_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    token_hash text NOT NULL,
    name character varying(255)
);

ALTER TABLE ONLY public.email_invitation FORCE ROW LEVEL SECURITY;


--
-- Name: est_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.est_credential (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    est_endpoint_id uuid NOT NULL,
    label character varying(64) DEFAULT ''::character varying NOT NULL,
    username character varying(64) NOT NULL,
    secret_hash text NOT NULL,
    identifier_pin text DEFAULT ''::text NOT NULL,
    expires_at timestamp without time zone,
    used_at timestamp without time zone,
    revoked_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT est_credential_username_not_blank CHECK ((btrim((username)::text) <> ''::text))
);

ALTER TABLE ONLY public.est_credential FORCE ROW LEVEL SECURITY;


--
-- Name: est_endpoint; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.est_endpoint (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    certificate_authority_id uuid NOT NULL,
    name character varying(64) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    validity_days integer DEFAULT 365 NOT NULL,
    renewal_window_days integer DEFAULT 73 NOT NULL,
    allowed_ekus text DEFAULT 'client_auth'::text NOT NULL,
    subject_pattern text DEFAULT ''::text NOT NULL,
    san_pattern text DEFAULT ''::text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    reenroll_requires_same_key boolean DEFAULT false NOT NULL,
    CONSTRAINT est_endpoint_name_not_blank CHECK ((btrim((name)::text) <> ''::text)),
    CONSTRAINT est_endpoint_renewal_window_days_check CHECK (((renewal_window_days >= 1) AND (renewal_window_days <= 365))),
    CONSTRAINT est_endpoint_validity_days_check CHECK (((validity_days >= 1) AND (validity_days <= 3650)))
);

ALTER TABLE ONLY public.est_endpoint FORCE ROW LEVEL SECURITY;


--
-- Name: est_enrollment; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.est_enrollment (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    est_endpoint_id uuid NOT NULL,
    est_credential_id uuid,
    certificate_id uuid,
    subject text DEFAULT ''::text NOT NULL,
    operation character varying(16) NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    status character varying(16) DEFAULT 'issued'::character varying NOT NULL,
    failure_reason text DEFAULT ''::text NOT NULL,
    CONSTRAINT est_enrollment_operation_check CHECK (((operation)::text = ANY ((ARRAY['enroll'::character varying, 'reenroll'::character varying])::text[]))),
    CONSTRAINT est_enrollment_status_check CHECK (((status)::text = ANY ((ARRAY['issued'::character varying, 'failed'::character varying])::text[])))
);

ALTER TABLE ONLY public.est_enrollment FORCE ROW LEVEL SECURITY;


--
-- Name: login_challenge; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.login_challenge (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    stage character varying(16) NOT NULL,
    pending_totp_secret bytea,
    attempts integer DEFAULT 0 NOT NULL,
    webauthn_session jsonb,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT login_challenge_stage_check CHECK (((stage)::text = ANY ((ARRAY['verify'::character varying, 'enroll'::character varying])::text[])))
);

ALTER TABLE ONLY public.login_challenge FORCE ROW LEVEL SECURITY;


--
-- Name: magic_link; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.magic_link (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    token_hash text NOT NULL
);

ALTER TABLE ONLY public.magic_link FORCE ROW LEVEL SECURITY;


--
-- Name: ocsp_response_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ocsp_response_cache (
    organization_id uuid NOT NULL,
    certificate_authority_id uuid NOT NULL,
    serial text NOT NULL,
    hash_algorithm integer NOT NULL,
    certificate_status character varying(32) NOT NULL,
    response_der bytea NOT NULL,
    this_update timestamp without time zone NOT NULL,
    next_update timestamp without time zone NOT NULL
);

ALTER TABLE ONLY public.ocsp_response_cache FORCE ROW LEVEL SECURITY;


--
-- Name: organization; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.organization (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    expiry_alerts_enabled boolean DEFAULT true NOT NULL,
    expiry_alert_days integer DEFAULT 30 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT organization_expiry_alert_days_check CHECK (((expiry_alert_days >= 1) AND (expiry_alert_days <= 365)))
);

ALTER TABLE ONLY public.organization FORCE ROW LEVEL SECURITY;


--
-- Name: scep_auth_method; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scep_auth_method (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    scep_endpoint_id uuid NOT NULL,
    method character varying(16) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    secret_hash text DEFAULT ''::text NOT NULL,
    username text DEFAULT ''::text NOT NULL,
    password_hash text DEFAULT ''::text NOT NULL,
    configured_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT scep_auth_method_method_check CHECK (((method)::text = ANY ((ARRAY['one_time'::character varying, 'static'::character varying, 'intune'::character varying, 'jamf'::character varying])::text[])))
);

ALTER TABLE ONLY public.scep_auth_method FORCE ROW LEVEL SECURITY;


--
-- Name: scep_challenge; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scep_challenge (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    scep_endpoint_id uuid NOT NULL,
    lookup_digest bytea NOT NULL,
    secret_hash text NOT NULL,
    expected_subject text DEFAULT ''::text NOT NULL,
    expected_sans text DEFAULT ''::text NOT NULL,
    external_id text DEFAULT ''::text NOT NULL,
    expires_at timestamp without time zone NOT NULL,
    used_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    expected_ekus text DEFAULT ''::text NOT NULL
);

ALTER TABLE ONLY public.scep_challenge FORCE ROW LEVEL SECURITY;


--
-- Name: scep_endpoint; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scep_endpoint (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    certificate_authority_id uuid NOT NULL,
    ra_certificate_pem text NOT NULL,
    ra_private_key_ciphertext bytea NOT NULL,
    name character varying(64) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    validity_days integer DEFAULT 365 NOT NULL,
    allowed_ekus text DEFAULT 'client_auth'::text NOT NULL,
    subject_pattern text DEFAULT ''::text NOT NULL,
    san_pattern text DEFAULT ''::text NOT NULL,
    allow_legacy_crypto boolean DEFAULT false NOT NULL,
    renewal_window_days integer DEFAULT 73 NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT scep_endpoint_name_not_blank CHECK ((btrim((name)::text) <> ''::text)),
    CONSTRAINT scep_endpoint_renewal_window_days_check CHECK (((renewal_window_days >= 1) AND (renewal_window_days <= 365))),
    CONSTRAINT scep_endpoint_validity_days_check CHECK (((validity_days >= 1) AND (validity_days <= 3650)))
);

ALTER TABLE ONLY public.scep_endpoint FORCE ROW LEVEL SECURITY;


--
-- Name: scep_intune_connection; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scep_intune_connection (
    organization_id uuid NOT NULL,
    tenant_id text NOT NULL,
    connected_at timestamp without time zone DEFAULT now() NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT scep_intune_connection_tenant_id_check CHECK ((tenant_id <> ''::text))
);

ALTER TABLE ONLY public.scep_intune_connection FORCE ROW LEVEL SECURITY;


--
-- Name: scep_transaction; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.scep_transaction (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid NOT NULL,
    scep_endpoint_id uuid NOT NULL,
    transaction_id text NOT NULL,
    csr_digest text NOT NULL,
    certificate_id uuid,
    message_type character varying(16) NOT NULL,
    status character varying(16) NOT NULL,
    authorization_source character varying(16) NOT NULL,
    failure_reason text DEFAULT ''::text NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    updated_at timestamp without time zone DEFAULT now() NOT NULL,
    signer_key_digest text DEFAULT ''::text NOT NULL,
    CONSTRAINT scep_transaction_status_check CHECK (((status)::text = ANY ((ARRAY['issued'::character varying, 'failed'::character varying])::text[])))
);

ALTER TABLE ONLY public.scep_transaction FORCE ROW LEVEL SECURITY;


--
-- Name: session; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.session (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    organization_id uuid,
    expires_at timestamp without time zone NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    stepped_up_at timestamp with time zone,
    webauthn_session jsonb,
    pending_totp_secret bytea,
    pending_totp_label character varying(64)
);

ALTER TABLE ONLY public.session FORCE ROW LEVEL SECURITY;


--
-- Name: user; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public."user" (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id uuid,
    email character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    role character varying(64) DEFAULT 'administrator'::character varying NOT NULL,
    CONSTRAINT user_role_check CHECK (((role)::text = ANY ((ARRAY['administrator'::character varying, 'certificate_manager'::character varying, 'auditor'::character varying])::text[])))
);

ALTER TABLE ONLY public."user" FORCE ROW LEVEL SECURITY;


--
-- Name: user_recovery_code; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_recovery_code (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    selector text NOT NULL,
    verifier_hash text NOT NULL,
    used_at timestamp without time zone,
    created_at timestamp without time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.user_recovery_code FORCE ROW LEVEL SECURITY;


--
-- Name: user_totp_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_totp_credential (
    user_id uuid NOT NULL,
    secret bytea NOT NULL,
    last_step bigint DEFAULT 0 NOT NULL,
    confirmed_at timestamp without time zone DEFAULT now() NOT NULL,
    last_used_at timestamp without time zone,
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    label character varying(64) DEFAULT ''::character varying NOT NULL
);

ALTER TABLE ONLY public.user_totp_credential FORCE ROW LEVEL SECURITY;


--
-- Name: user_webauthn_credential; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_webauthn_credential (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    attestation_type text DEFAULT ''::text NOT NULL,
    aaguid bytea DEFAULT '\x'::bytea NOT NULL,
    transports text DEFAULT ''::text NOT NULL,
    sign_count bigint DEFAULT 0 NOT NULL,
    backup_eligible boolean DEFAULT false NOT NULL,
    backup_state boolean DEFAULT false NOT NULL,
    clone_warning boolean DEFAULT false NOT NULL,
    label character varying(64) DEFAULT ''::character varying NOT NULL,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    last_used_at timestamp without time zone
);

ALTER TABLE ONLY public.user_webauthn_credential FORCE ROW LEVEL SECURITY;


--
-- Name: acme_account acme_account_acme_endpoint_id_jwk_thumbprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_account
    ADD CONSTRAINT acme_account_acme_endpoint_id_jwk_thumbprint_key UNIQUE (acme_endpoint_id, jwk_thumbprint);


--
-- Name: acme_account acme_account_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_account
    ADD CONSTRAINT acme_account_pkey PRIMARY KEY (id);


--
-- Name: acme_authorization acme_authorization_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_authorization
    ADD CONSTRAINT acme_authorization_pkey PRIMARY KEY (id);


--
-- Name: acme_challenge acme_challenge_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_challenge
    ADD CONSTRAINT acme_challenge_pkey PRIMARY KEY (id);


--
-- Name: acme_eab_credential acme_eab_credential_acme_endpoint_id_kid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_eab_credential
    ADD CONSTRAINT acme_eab_credential_acme_endpoint_id_kid_key UNIQUE (acme_endpoint_id, kid);


--
-- Name: acme_eab_credential acme_eab_credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_eab_credential
    ADD CONSTRAINT acme_eab_credential_pkey PRIMARY KEY (id);


--
-- Name: acme_endpoint acme_endpoint_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_endpoint
    ADD CONSTRAINT acme_endpoint_pkey PRIMARY KEY (id);


--
-- Name: acme_nonce acme_nonce_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_nonce
    ADD CONSTRAINT acme_nonce_pkey PRIMARY KEY (value);


--
-- Name: acme_order acme_order_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_order
    ADD CONSTRAINT acme_order_pkey PRIMARY KEY (id);


--
-- Name: audit_event audit_event_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_event
    ADD CONSTRAINT audit_event_pkey PRIMARY KEY (id);


--
-- Name: ca_import_job ca_import_job_kms_crypto_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_import_job
    ADD CONSTRAINT ca_import_job_kms_crypto_key_key UNIQUE (kms_crypto_key);


--
-- Name: ca_import_job ca_import_job_kms_import_job_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_import_job
    ADD CONSTRAINT ca_import_job_kms_import_job_key UNIQUE (kms_import_job);


--
-- Name: ca_import_job ca_import_job_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_import_job
    ADD CONSTRAINT ca_import_job_pkey PRIMARY KEY (id);


--
-- Name: certificate_authority certificate_authority_kms_key_version_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_authority
    ADD CONSTRAINT certificate_authority_kms_key_version_key UNIQUE (kms_key_version);


--
-- Name: certificate_authority certificate_authority_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_authority
    ADD CONSTRAINT certificate_authority_pkey PRIMARY KEY (id);


--
-- Name: certificate certificate_organization_id_serial_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate
    ADD CONSTRAINT certificate_organization_id_serial_key UNIQUE (organization_id, serial);


--
-- Name: certificate certificate_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate
    ADD CONSTRAINT certificate_pkey PRIMARY KEY (id);


--
-- Name: certificate_revocation certificate_revocation_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_revocation
    ADD CONSTRAINT certificate_revocation_pkey PRIMARY KEY (id);


--
-- Name: certificate_signing_audit certificate_signing_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_signing_audit
    ADD CONSTRAINT certificate_signing_audit_pkey PRIMARY KEY (id);


--
-- Name: crl_publication crl_publication_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.crl_publication
    ADD CONSTRAINT crl_publication_pkey PRIMARY KEY (certificate_authority_id);


--
-- Name: email_invitation email_invitation_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_invitation
    ADD CONSTRAINT email_invitation_pkey PRIMARY KEY (id);


--
-- Name: est_credential est_credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_credential
    ADD CONSTRAINT est_credential_pkey PRIMARY KEY (id);


--
-- Name: est_endpoint est_endpoint_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_endpoint
    ADD CONSTRAINT est_endpoint_pkey PRIMARY KEY (id);


--
-- Name: est_enrollment est_enrollment_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_enrollment
    ADD CONSTRAINT est_enrollment_pkey PRIMARY KEY (id);


--
-- Name: login_challenge login_challenge_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_challenge
    ADD CONSTRAINT login_challenge_pkey PRIMARY KEY (id);


--
-- Name: magic_link magic_link_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.magic_link
    ADD CONSTRAINT magic_link_pkey PRIMARY KEY (id);


--
-- Name: ocsp_response_cache ocsp_response_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ocsp_response_cache
    ADD CONSTRAINT ocsp_response_cache_pkey PRIMARY KEY (certificate_authority_id, serial, hash_algorithm);


--
-- Name: organization organization_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.organization
    ADD CONSTRAINT organization_pkey PRIMARY KEY (id);


--
-- Name: scep_auth_method scep_auth_method_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_auth_method
    ADD CONSTRAINT scep_auth_method_pkey PRIMARY KEY (id);


--
-- Name: scep_auth_method scep_auth_method_scep_endpoint_id_method_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_auth_method
    ADD CONSTRAINT scep_auth_method_scep_endpoint_id_method_key UNIQUE (scep_endpoint_id, method);


--
-- Name: scep_challenge scep_challenge_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_challenge
    ADD CONSTRAINT scep_challenge_pkey PRIMARY KEY (id);


--
-- Name: scep_challenge scep_challenge_scep_endpoint_id_lookup_digest_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_challenge
    ADD CONSTRAINT scep_challenge_scep_endpoint_id_lookup_digest_key UNIQUE (scep_endpoint_id, lookup_digest);


--
-- Name: scep_endpoint scep_endpoint_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_endpoint
    ADD CONSTRAINT scep_endpoint_pkey PRIMARY KEY (id);


--
-- Name: scep_intune_connection scep_intune_connection_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_intune_connection
    ADD CONSTRAINT scep_intune_connection_pkey PRIMARY KEY (organization_id);


--
-- Name: scep_intune_connection scep_intune_connection_tenant_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_intune_connection
    ADD CONSTRAINT scep_intune_connection_tenant_id_key UNIQUE (tenant_id);


--
-- Name: scep_transaction scep_transaction_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_transaction
    ADD CONSTRAINT scep_transaction_pkey PRIMARY KEY (id);


--
-- Name: scep_transaction scep_transaction_scep_endpoint_id_transaction_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_transaction
    ADD CONSTRAINT scep_transaction_scep_endpoint_id_transaction_id_key UNIQUE (scep_endpoint_id, transaction_id);


--
-- Name: session session_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session
    ADD CONSTRAINT session_pkey PRIMARY KEY (id);


--
-- Name: user user_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_pkey PRIMARY KEY (id);


--
-- Name: user_recovery_code user_recovery_code_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_recovery_code
    ADD CONSTRAINT user_recovery_code_pkey PRIMARY KEY (id);


--
-- Name: user_recovery_code user_recovery_code_selector_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_recovery_code
    ADD CONSTRAINT user_recovery_code_selector_key UNIQUE (selector);


--
-- Name: user_totp_credential user_totp_credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_totp_credential
    ADD CONSTRAINT user_totp_credential_pkey PRIMARY KEY (id);


--
-- Name: user_webauthn_credential user_webauthn_credential_credential_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_webauthn_credential
    ADD CONSTRAINT user_webauthn_credential_credential_id_key UNIQUE (credential_id);


--
-- Name: user_webauthn_credential user_webauthn_credential_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_webauthn_credential
    ADD CONSTRAINT user_webauthn_credential_pkey PRIMARY KEY (id);


--
-- Name: acme_account_endpoint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_account_endpoint_idx ON public.acme_account USING btree (acme_endpoint_id);


--
-- Name: acme_authorization_order_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_authorization_order_idx ON public.acme_authorization USING btree (acme_order_id);


--
-- Name: acme_challenge_authorization_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_challenge_authorization_idx ON public.acme_challenge USING btree (acme_authorization_id);


--
-- Name: acme_eab_credential_endpoint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_eab_credential_endpoint_idx ON public.acme_eab_credential USING btree (acme_endpoint_id, created_at DESC);


--
-- Name: acme_endpoint_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_endpoint_org_idx ON public.acme_endpoint USING btree (organization_id);


--
-- Name: acme_endpoint_org_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX acme_endpoint_org_name_key ON public.acme_endpoint USING btree (organization_id, lower((name)::text));


--
-- Name: acme_nonce_issued_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_nonce_issued_idx ON public.acme_nonce USING btree (issued_at);


--
-- Name: acme_order_account_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_order_account_idx ON public.acme_order USING btree (acme_account_id, created_at DESC);


--
-- Name: acme_order_endpoint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_order_endpoint_idx ON public.acme_order USING btree (acme_endpoint_id, created_at DESC);


--
-- Name: acme_order_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX acme_order_expiry_idx ON public.acme_order USING btree (expires_at) WHERE ((status)::text = ANY ((ARRAY['pending'::character varying, 'ready'::character varying])::text[]));


--
-- Name: audit_event_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX audit_event_org_idx ON public.audit_event USING btree (organization_id, created_at DESC);


--
-- Name: ca_import_job_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ca_import_job_org_idx ON public.ca_import_job USING btree (organization_id);


--
-- Name: certificate_audit_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_audit_org_idx ON public.certificate_signing_audit USING btree (organization_id);


--
-- Name: certificate_authority_one_root_per_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX certificate_authority_one_root_per_org_idx ON public.certificate_authority USING btree (organization_id) WHERE (((type)::text = 'root'::text) AND ((status)::text <> 'deleted'::text));


--
-- Name: certificate_authority_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_authority_org_idx ON public.certificate_authority USING btree (organization_id);


--
-- Name: certificate_ca_serial_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_ca_serial_idx ON public.certificate USING btree (organization_id, certificate_authority_id, serial);


--
-- Name: certificate_expiry_alert_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_expiry_alert_idx ON public.certificate USING btree (organization_id, expires_at) WHERE ((status)::text = 'issued'::text);


--
-- Name: certificate_org_active_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_org_active_idx ON public.certificate USING btree (organization_id, status, expires_at);


--
-- Name: certificate_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_org_idx ON public.certificate USING btree (organization_id);


--
-- Name: certificate_revocation_certificate_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX certificate_revocation_certificate_idx ON public.certificate_revocation USING btree (certificate_id);


--
-- Name: certificate_revoked_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX certificate_revoked_idx ON public.certificate USING btree (organization_id, status, revoked_at);


--
-- Name: email_invitation_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_invitation_org_idx ON public.email_invitation USING btree (organization_id);


--
-- Name: email_invitation_pending_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX email_invitation_pending_idx ON public.email_invitation USING btree (organization_id, created_at DESC) WHERE (accepted_at IS NULL);


--
-- Name: email_invitation_token_hash_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX email_invitation_token_hash_key ON public.email_invitation USING btree (token_hash);


--
-- Name: est_credential_endpoint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX est_credential_endpoint_idx ON public.est_credential USING btree (est_endpoint_id, created_at DESC);


--
-- Name: est_credential_endpoint_username_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX est_credential_endpoint_username_key ON public.est_credential USING btree (est_endpoint_id, lower((username)::text)) WHERE (revoked_at IS NULL);


--
-- Name: est_endpoint_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX est_endpoint_org_idx ON public.est_endpoint USING btree (organization_id);


--
-- Name: est_endpoint_org_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX est_endpoint_org_name_key ON public.est_endpoint USING btree (organization_id, lower((name)::text));


--
-- Name: est_enrollment_endpoint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX est_enrollment_endpoint_idx ON public.est_enrollment USING btree (est_endpoint_id, created_at DESC);


--
-- Name: est_enrollment_subject_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX est_enrollment_subject_idx ON public.est_enrollment USING btree (est_endpoint_id, subject);


--
-- Name: login_challenge_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX login_challenge_expiry_idx ON public.login_challenge USING btree (expires_at);


--
-- Name: magic_link_expiry_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX magic_link_expiry_idx ON public.magic_link USING btree (expires_at);


--
-- Name: magic_link_token_hash_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX magic_link_token_hash_key ON public.magic_link USING btree (token_hash);


--
-- Name: organization_singleton; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX organization_singleton ON public.organization USING btree ((true));


--
-- Name: scep_auth_method_endpoint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scep_auth_method_endpoint_idx ON public.scep_auth_method USING btree (scep_endpoint_id);


--
-- Name: scep_challenge_endpoint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scep_challenge_endpoint_idx ON public.scep_challenge USING btree (scep_endpoint_id, expires_at) WHERE (used_at IS NULL);


--
-- Name: scep_endpoint_org_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scep_endpoint_org_idx ON public.scep_endpoint USING btree (organization_id);


--
-- Name: scep_endpoint_org_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX scep_endpoint_org_name_key ON public.scep_endpoint USING btree (organization_id, lower((name)::text));


--
-- Name: scep_transaction_endpoint_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX scep_transaction_endpoint_idx ON public.scep_transaction USING btree (scep_endpoint_id, created_at DESC);


--
-- Name: user_recovery_code_live_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_recovery_code_live_idx ON public.user_recovery_code USING btree (user_id) WHERE (used_at IS NULL);


--
-- Name: user_totp_credential_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_totp_credential_user_idx ON public.user_totp_credential USING btree (user_id);


--
-- Name: user_webauthn_credential_user_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX user_webauthn_credential_user_idx ON public.user_webauthn_credential USING btree (user_id);


--
-- Name: acme_account acme_account_acme_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_account
    ADD CONSTRAINT acme_account_acme_endpoint_id_fkey FOREIGN KEY (acme_endpoint_id) REFERENCES public.acme_endpoint(id) ON DELETE CASCADE;


--
-- Name: acme_account acme_account_eab_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_account
    ADD CONSTRAINT acme_account_eab_credential_id_fkey FOREIGN KEY (eab_credential_id) REFERENCES public.acme_eab_credential(id) ON DELETE SET NULL;


--
-- Name: acme_account acme_account_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_account
    ADD CONSTRAINT acme_account_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: acme_authorization acme_authorization_acme_order_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_authorization
    ADD CONSTRAINT acme_authorization_acme_order_id_fkey FOREIGN KEY (acme_order_id) REFERENCES public.acme_order(id) ON DELETE CASCADE;


--
-- Name: acme_authorization acme_authorization_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_authorization
    ADD CONSTRAINT acme_authorization_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: acme_challenge acme_challenge_acme_authorization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_challenge
    ADD CONSTRAINT acme_challenge_acme_authorization_id_fkey FOREIGN KEY (acme_authorization_id) REFERENCES public.acme_authorization(id) ON DELETE CASCADE;


--
-- Name: acme_challenge acme_challenge_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_challenge
    ADD CONSTRAINT acme_challenge_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: acme_eab_credential acme_eab_credential_acme_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_eab_credential
    ADD CONSTRAINT acme_eab_credential_acme_endpoint_id_fkey FOREIGN KEY (acme_endpoint_id) REFERENCES public.acme_endpoint(id) ON DELETE CASCADE;


--
-- Name: acme_eab_credential acme_eab_credential_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_eab_credential
    ADD CONSTRAINT acme_eab_credential_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: acme_endpoint acme_endpoint_certificate_authority_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_endpoint
    ADD CONSTRAINT acme_endpoint_certificate_authority_id_fkey FOREIGN KEY (certificate_authority_id) REFERENCES public.certificate_authority(id);


--
-- Name: acme_endpoint acme_endpoint_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_endpoint
    ADD CONSTRAINT acme_endpoint_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: acme_nonce acme_nonce_acme_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_nonce
    ADD CONSTRAINT acme_nonce_acme_endpoint_id_fkey FOREIGN KEY (acme_endpoint_id) REFERENCES public.acme_endpoint(id) ON DELETE CASCADE;


--
-- Name: acme_nonce acme_nonce_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_nonce
    ADD CONSTRAINT acme_nonce_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: acme_order acme_order_acme_account_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_order
    ADD CONSTRAINT acme_order_acme_account_id_fkey FOREIGN KEY (acme_account_id) REFERENCES public.acme_account(id) ON DELETE CASCADE;


--
-- Name: acme_order acme_order_acme_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_order
    ADD CONSTRAINT acme_order_acme_endpoint_id_fkey FOREIGN KEY (acme_endpoint_id) REFERENCES public.acme_endpoint(id) ON DELETE CASCADE;


--
-- Name: acme_order acme_order_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_order
    ADD CONSTRAINT acme_order_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificate(id);


--
-- Name: acme_order acme_order_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.acme_order
    ADD CONSTRAINT acme_order_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: audit_event audit_event_actor_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_event
    ADD CONSTRAINT audit_event_actor_user_id_fkey FOREIGN KEY (actor_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: audit_event audit_event_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_event
    ADD CONSTRAINT audit_event_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: ca_import_job ca_import_job_cancelled_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_import_job
    ADD CONSTRAINT ca_import_job_cancelled_by_fkey FOREIGN KEY (cancelled_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: ca_import_job ca_import_job_certificate_authority_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_import_job
    ADD CONSTRAINT ca_import_job_certificate_authority_id_fkey FOREIGN KEY (certificate_authority_id) REFERENCES public.certificate_authority(id);


--
-- Name: ca_import_job ca_import_job_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_import_job
    ADD CONSTRAINT ca_import_job_created_by_fkey FOREIGN KEY (created_by) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: ca_import_job ca_import_job_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ca_import_job
    ADD CONSTRAINT ca_import_job_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: certificate_authority certificate_authority_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_authority
    ADD CONSTRAINT certificate_authority_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: certificate_authority certificate_authority_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_authority
    ADD CONSTRAINT certificate_authority_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.certificate_authority(id);


--
-- Name: certificate certificate_certificate_authority_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate
    ADD CONSTRAINT certificate_certificate_authority_id_fkey FOREIGN KEY (certificate_authority_id) REFERENCES public.certificate_authority(id);


--
-- Name: certificate certificate_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate
    ADD CONSTRAINT certificate_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: certificate_revocation certificate_revocation_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_revocation
    ADD CONSTRAINT certificate_revocation_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificate(id) ON DELETE CASCADE;


--
-- Name: certificate_revocation certificate_revocation_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_revocation
    ADD CONSTRAINT certificate_revocation_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: certificate_signing_audit certificate_signing_audit_certificate_authority_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_signing_audit
    ADD CONSTRAINT certificate_signing_audit_certificate_authority_id_fkey FOREIGN KEY (certificate_authority_id) REFERENCES public.certificate_authority(id);


--
-- Name: certificate_signing_audit certificate_signing_audit_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_signing_audit
    ADD CONSTRAINT certificate_signing_audit_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: certificate_signing_audit certificate_signing_audit_requester_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.certificate_signing_audit
    ADD CONSTRAINT certificate_signing_audit_requester_user_id_fkey FOREIGN KEY (requester_user_id) REFERENCES public."user"(id) ON DELETE SET NULL;


--
-- Name: crl_publication crl_publication_certificate_authority_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.crl_publication
    ADD CONSTRAINT crl_publication_certificate_authority_id_fkey FOREIGN KEY (certificate_authority_id) REFERENCES public.certificate_authority(id) ON DELETE CASCADE;


--
-- Name: crl_publication crl_publication_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.crl_publication
    ADD CONSTRAINT crl_publication_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: email_invitation email_invitation_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_invitation
    ADD CONSTRAINT email_invitation_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: est_credential est_credential_est_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_credential
    ADD CONSTRAINT est_credential_est_endpoint_id_fkey FOREIGN KEY (est_endpoint_id) REFERENCES public.est_endpoint(id) ON DELETE CASCADE;


--
-- Name: est_credential est_credential_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_credential
    ADD CONSTRAINT est_credential_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: est_endpoint est_endpoint_certificate_authority_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_endpoint
    ADD CONSTRAINT est_endpoint_certificate_authority_id_fkey FOREIGN KEY (certificate_authority_id) REFERENCES public.certificate_authority(id);


--
-- Name: est_endpoint est_endpoint_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_endpoint
    ADD CONSTRAINT est_endpoint_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: est_enrollment est_enrollment_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_enrollment
    ADD CONSTRAINT est_enrollment_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificate(id);


--
-- Name: est_enrollment est_enrollment_est_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_enrollment
    ADD CONSTRAINT est_enrollment_est_credential_id_fkey FOREIGN KEY (est_credential_id) REFERENCES public.est_credential(id) ON DELETE SET NULL;


--
-- Name: est_enrollment est_enrollment_est_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_enrollment
    ADD CONSTRAINT est_enrollment_est_endpoint_id_fkey FOREIGN KEY (est_endpoint_id) REFERENCES public.est_endpoint(id) ON DELETE CASCADE;


--
-- Name: est_enrollment est_enrollment_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.est_enrollment
    ADD CONSTRAINT est_enrollment_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: login_challenge login_challenge_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_challenge
    ADD CONSTRAINT login_challenge_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: magic_link magic_link_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.magic_link
    ADD CONSTRAINT magic_link_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: ocsp_response_cache ocsp_response_cache_certificate_authority_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ocsp_response_cache
    ADD CONSTRAINT ocsp_response_cache_certificate_authority_id_fkey FOREIGN KEY (certificate_authority_id) REFERENCES public.certificate_authority(id) ON DELETE CASCADE;


--
-- Name: ocsp_response_cache ocsp_response_cache_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ocsp_response_cache
    ADD CONSTRAINT ocsp_response_cache_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: scep_auth_method scep_auth_method_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_auth_method
    ADD CONSTRAINT scep_auth_method_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: scep_auth_method scep_auth_method_scep_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_auth_method
    ADD CONSTRAINT scep_auth_method_scep_endpoint_id_fkey FOREIGN KEY (scep_endpoint_id) REFERENCES public.scep_endpoint(id) ON DELETE CASCADE;


--
-- Name: scep_challenge scep_challenge_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_challenge
    ADD CONSTRAINT scep_challenge_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: scep_challenge scep_challenge_scep_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_challenge
    ADD CONSTRAINT scep_challenge_scep_endpoint_id_fkey FOREIGN KEY (scep_endpoint_id) REFERENCES public.scep_endpoint(id) ON DELETE CASCADE;


--
-- Name: scep_endpoint scep_endpoint_certificate_authority_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_endpoint
    ADD CONSTRAINT scep_endpoint_certificate_authority_id_fkey FOREIGN KEY (certificate_authority_id) REFERENCES public.certificate_authority(id);


--
-- Name: scep_endpoint scep_endpoint_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_endpoint
    ADD CONSTRAINT scep_endpoint_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: scep_intune_connection scep_intune_connection_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_intune_connection
    ADD CONSTRAINT scep_intune_connection_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: scep_transaction scep_transaction_certificate_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_transaction
    ADD CONSTRAINT scep_transaction_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificate(id);


--
-- Name: scep_transaction scep_transaction_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_transaction
    ADD CONSTRAINT scep_transaction_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id) ON DELETE CASCADE;


--
-- Name: scep_transaction scep_transaction_scep_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.scep_transaction
    ADD CONSTRAINT scep_transaction_scep_endpoint_id_fkey FOREIGN KEY (scep_endpoint_id) REFERENCES public.scep_endpoint(id) ON DELETE CASCADE;


--
-- Name: session session_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session
    ADD CONSTRAINT session_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id);


--
-- Name: session session_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.session
    ADD CONSTRAINT session_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: user user_organization_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public."user"
    ADD CONSTRAINT user_organization_id_fkey FOREIGN KEY (organization_id) REFERENCES public.organization(id);


--
-- Name: user_recovery_code user_recovery_code_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_recovery_code
    ADD CONSTRAINT user_recovery_code_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: user_totp_credential user_totp_credential_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_totp_credential
    ADD CONSTRAINT user_totp_credential_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: user_webauthn_credential user_webauthn_credential_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_webauthn_credential
    ADD CONSTRAINT user_webauthn_credential_user_id_fkey FOREIGN KEY (user_id) REFERENCES public."user"(id) ON DELETE CASCADE;


--
-- Name: acme_account; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.acme_account ENABLE ROW LEVEL SECURITY;

--
-- Name: acme_account acme_account_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY acme_account_rls ON public.acme_account USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: acme_authorization; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.acme_authorization ENABLE ROW LEVEL SECURITY;

--
-- Name: acme_authorization acme_authorization_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY acme_authorization_rls ON public.acme_authorization USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: acme_challenge; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.acme_challenge ENABLE ROW LEVEL SECURITY;

--
-- Name: acme_challenge acme_challenge_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY acme_challenge_rls ON public.acme_challenge USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: acme_eab_credential; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.acme_eab_credential ENABLE ROW LEVEL SECURITY;

--
-- Name: acme_eab_credential acme_eab_credential_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY acme_eab_credential_rls ON public.acme_eab_credential USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: acme_endpoint; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.acme_endpoint ENABLE ROW LEVEL SECURITY;

--
-- Name: acme_endpoint acme_endpoint_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY acme_endpoint_rls ON public.acme_endpoint USING (((organization_id = public.app_current_uuid('app.organization_id'::text)) OR ((id = public.app_current_uuid('app.acme_endpoint_id'::text)) AND enabled))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: acme_nonce; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.acme_nonce ENABLE ROW LEVEL SECURITY;

--
-- Name: acme_nonce acme_nonce_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY acme_nonce_rls ON public.acme_nonce USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: acme_order; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.acme_order ENABLE ROW LEVEL SECURITY;

--
-- Name: acme_order acme_order_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY acme_order_rls ON public.acme_order USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: audit_event; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.audit_event ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_event audit_event_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY audit_event_insert ON public.audit_event FOR INSERT WITH CHECK (((organization_id = public.app_current_uuid('app.organization_id'::text)) OR (current_setting('app.auth_flow'::text, true) = 'true'::text)));


--
-- Name: audit_event audit_event_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY audit_event_select ON public.audit_event FOR SELECT USING ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: ca_import_job; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ca_import_job ENABLE ROW LEVEL SECURITY;

--
-- Name: ca_import_job ca_import_job_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY ca_import_job_rls ON public.ca_import_job USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: certificate; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.certificate ENABLE ROW LEVEL SECURITY;

--
-- Name: certificate_authority; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.certificate_authority ENABLE ROW LEVEL SECURITY;

--
-- Name: certificate_authority certificate_authority_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY certificate_authority_rls ON public.certificate_authority USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: certificate_revocation; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.certificate_revocation ENABLE ROW LEVEL SECURITY;

--
-- Name: certificate_revocation certificate_revocation_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY certificate_revocation_rls ON public.certificate_revocation USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: certificate certificate_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY certificate_rls ON public.certificate USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: certificate_signing_audit; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.certificate_signing_audit ENABLE ROW LEVEL SECURITY;

--
-- Name: certificate_signing_audit certificate_signing_audit_insert; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY certificate_signing_audit_insert ON public.certificate_signing_audit FOR INSERT WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: certificate_signing_audit certificate_signing_audit_select; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY certificate_signing_audit_select ON public.certificate_signing_audit FOR SELECT USING ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: crl_publication; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.crl_publication ENABLE ROW LEVEL SECURITY;

--
-- Name: crl_publication crl_publication_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY crl_publication_rls ON public.crl_publication USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: email_invitation; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.email_invitation ENABLE ROW LEVEL SECURITY;

--
-- Name: email_invitation email_invitation_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY email_invitation_rls ON public.email_invitation USING (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (organization_id = public.app_current_uuid('app.organization_id'::text)))) WITH CHECK (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (organization_id = public.app_current_uuid('app.organization_id'::text))));


--
-- Name: est_credential; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.est_credential ENABLE ROW LEVEL SECURITY;

--
-- Name: est_credential est_credential_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY est_credential_rls ON public.est_credential USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: est_endpoint; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.est_endpoint ENABLE ROW LEVEL SECURITY;

--
-- Name: est_endpoint est_endpoint_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY est_endpoint_rls ON public.est_endpoint USING (((organization_id = public.app_current_uuid('app.organization_id'::text)) OR ((id = public.app_current_uuid('app.est_endpoint_id'::text)) AND enabled))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: est_enrollment; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.est_enrollment ENABLE ROW LEVEL SECURITY;

--
-- Name: est_enrollment est_enrollment_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY est_enrollment_rls ON public.est_enrollment USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: login_challenge; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.login_challenge ENABLE ROW LEVEL SECURITY;

--
-- Name: login_challenge login_challenge_auth_flow; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY login_challenge_auth_flow ON public.login_challenge USING ((current_setting('app.auth_flow'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.auth_flow'::text, true) = 'true'::text));


--
-- Name: magic_link; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.magic_link ENABLE ROW LEVEL SECURITY;

--
-- Name: magic_link magic_link_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY magic_link_rls ON public.magic_link USING (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (EXISTS ( SELECT 1
   FROM public."user"
  WHERE (("user".id = magic_link.user_id) AND ("user".organization_id = public.app_current_uuid('app.organization_id'::text))))))) WITH CHECK (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (EXISTS ( SELECT 1
   FROM public."user"
  WHERE (("user".id = magic_link.user_id) AND ("user".organization_id = public.app_current_uuid('app.organization_id'::text)))))));


--
-- Name: ocsp_response_cache; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ocsp_response_cache ENABLE ROW LEVEL SECURITY;

--
-- Name: ocsp_response_cache ocsp_response_cache_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY ocsp_response_cache_rls ON public.ocsp_response_cache USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: organization; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.organization ENABLE ROW LEVEL SECURITY;

--
-- Name: organization organization_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY organization_rls ON public.organization USING (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (id = public.app_current_uuid('app.organization_id'::text)))) WITH CHECK (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (id = public.app_current_uuid('app.organization_id'::text))));


--
-- Name: scep_auth_method; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scep_auth_method ENABLE ROW LEVEL SECURITY;

--
-- Name: scep_auth_method scep_auth_method_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY scep_auth_method_rls ON public.scep_auth_method USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: scep_challenge; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scep_challenge ENABLE ROW LEVEL SECURITY;

--
-- Name: scep_challenge scep_challenge_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY scep_challenge_rls ON public.scep_challenge USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: scep_endpoint; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scep_endpoint ENABLE ROW LEVEL SECURITY;

--
-- Name: scep_endpoint scep_endpoint_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY scep_endpoint_rls ON public.scep_endpoint USING (((organization_id = public.app_current_uuid('app.organization_id'::text)) OR ((id = public.app_current_uuid('app.scep_endpoint_id'::text)) AND enabled))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: scep_intune_connection; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scep_intune_connection ENABLE ROW LEVEL SECURITY;

--
-- Name: scep_intune_connection scep_intune_connection_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY scep_intune_connection_rls ON public.scep_intune_connection USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: scep_transaction; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.scep_transaction ENABLE ROW LEVEL SECURITY;

--
-- Name: scep_transaction scep_transaction_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY scep_transaction_rls ON public.scep_transaction USING ((organization_id = public.app_current_uuid('app.organization_id'::text))) WITH CHECK ((organization_id = public.app_current_uuid('app.organization_id'::text)));


--
-- Name: session; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.session ENABLE ROW LEVEL SECURITY;

--
-- Name: session session_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY session_rls ON public.session USING (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (id = public.app_current_uuid('app.session_id'::text)) OR (organization_id = public.app_current_uuid('app.organization_id'::text)))) WITH CHECK (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (id = public.app_current_uuid('app.session_id'::text)) OR (organization_id = public.app_current_uuid('app.organization_id'::text))));


--
-- Name: user; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public."user" ENABLE ROW LEVEL SECURITY;

--
-- Name: user_recovery_code; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_recovery_code ENABLE ROW LEVEL SECURITY;

--
-- Name: user_recovery_code user_recovery_code_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_recovery_code_rls ON public.user_recovery_code USING (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (user_id = public.app_current_uuid('app.user_id'::text)))) WITH CHECK (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (user_id = public.app_current_uuid('app.user_id'::text))));


--
-- Name: user user_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_rls ON public."user" USING (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (organization_id = public.app_current_uuid('app.organization_id'::text)) OR (id = public.app_current_uuid('app.user_id'::text)) OR (EXISTS ( SELECT 1
   FROM public.session
  WHERE ((session.id = public.app_current_uuid('app.session_id'::text)) AND (session.user_id = "user".id) AND (session.expires_at > now())))))) WITH CHECK (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (organization_id = public.app_current_uuid('app.organization_id'::text))));


--
-- Name: user_totp_credential; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_totp_credential ENABLE ROW LEVEL SECURITY;

--
-- Name: user_totp_credential user_totp_credential_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_totp_credential_rls ON public.user_totp_credential USING (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (user_id = public.app_current_uuid('app.user_id'::text)))) WITH CHECK (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (user_id = public.app_current_uuid('app.user_id'::text))));


--
-- Name: user_webauthn_credential; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_webauthn_credential ENABLE ROW LEVEL SECURITY;

--
-- Name: user_webauthn_credential user_webauthn_credential_rls; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY user_webauthn_credential_rls ON public.user_webauthn_credential USING (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (user_id = public.app_current_uuid('app.user_id'::text)))) WITH CHECK (((current_setting('app.auth_flow'::text, true) = 'true'::text) OR (user_id = public.app_current_uuid('app.user_id'::text))));


--
-- PostgreSQL database dump complete
--

