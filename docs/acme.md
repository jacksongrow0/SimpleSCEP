# ACME operations

An organization runs one or more RFC 8555 endpoints, each with its own directory URL:

`https://your-simple-scep-host/acme/<endpoint-id>/directory`

That URL is the only thing a client is configured with; every other resource it needs, it discovers from there. HTTPS is required in production.

Endpoints are created from **SCEP · ACME · EST → Add endpoint** on the ACME tab, which names the endpoint and binds it to an active issuing CA. The CA binding is fixed once created; the name and everything under Issuance policy can change later. Unlike a SCEP endpoint, an ACME endpoint mints no key material of its own — clients sign with account keys they generate and keep.

Where SCEP serves MDM-managed devices, ACME serves everything that renews itself: ingress controllers, load balancers, reverse proxies, internal service meshes. cert-manager, Caddy, Traefik, certbot, acme.sh and lego all already speak it, so a customer points an existing tool at the directory URL rather than writing an integration.

## Why your client's authorizations come back already valid

This is the one place SimpleSCEP deviates from a public ACME server, and it is worth understanding before the first client is configured, because a client that skips a challenge you expected to watch looks like something went wrong.

Public ACME proves control of a name by reaching back to the requester: `http-01` fetches a token from the host being named, `tls-alpn-01` opens a TLS connection to it, and `dns-01` reads a TXT record from public DNS. SimpleSCEP instead issues from **private** CAs, usually for names such as `vpn.example.internal` that resolve only inside the operator's network. Requiring public inbound reachability would either fail or unnecessarily expose internal hosts.

So the proof happens once, at registration, instead of once per name. A client registers with an **External Account Binding** credential (RFC 8555 §7.3.4) that an administrator minted in the console. That credential is what says "this client belongs to this organization and may enroll at this endpoint" — the direct analogue of SCEP's one-time challenge or shared secret. What the client may then ask _for_ is decided by two things:

1. the **identifier pin** on the credential it registered with, if you set one — an exact list of names, and nothing else is issued to that account, whatever the endpoint policy says;
2. the endpoint's **SAN pattern**, which applies to every account on the endpoint.

Authorizations are therefore created `valid` the moment an order is placed, and each carries a single challenge of type `external-account-binding-01` in the `valid` state, so the object graph a client walks is well-formed. Every widely deployed client branches on the authorization's _status_ rather than on the challenge type, and goes straight to finalize when it is already valid.

The practical consequences:

- **You cannot issue for a name a credential or the SAN pattern does not allow**, so those two settings are the whole access-control story. Treat a credential with no pin and a `.*` SAN pattern the way you would treat a SCEP shared secret with a permissive usage list.
- **Wildcard identifiers are refused.** A wildcard can only be justified by `dns-01`, which this server does not run, so issuing one would be issuing on no evidence at all. Name each host.
- Give each population you police differently its own endpoint. Validity, subject and SAN patterns, and the permitted extended key usages are all per-endpoint.

## External account credentials

A credential is a **key identifier** (`kid`) and an **HMAC key**. Mint one per client from the endpoint page.

The HMAC key is shown exactly once, when it is created. It is stored sealed under the same key-protection provider that holds CA keys, and it is never rendered again — not to you, not to support. If it is lost, mint another; there is no recovery path, by design. (This is the one place ACME cannot copy SCEP's storage: verifying a binding is an HMAC computation, so the server needs the key material itself rather than the argon2id verifier a SCEP challenge stores.)

Options when minting:

| Option             | What it does                                                                                                                                                              |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Label              | For your records only. Not sent to the client.                                                                                                                            |
| Pin to these names | Comma-separated exact identifiers. An account registered with this credential can order only these, whatever the endpoint's SAN pattern would otherwise allow.            |
| Expires after      | Bounds how long the credential can _register_ an account. A client that has already registered keeps working after the credential expires, so a short life here is cheap. |
| Single use         | The credential binds one account and is then spent. Right when handing it to one machine; leave it off to provision a fleet from one credential.                          |

**Revoking a credential also deactivates every account it registered.** Withdrawing the key that let a client in should stop that client, not merely stop the next one — so an account whose credential was revoked can no longer order. Certificates already issued are not revoked; do that from the certificates page if they should stop working.

The pin is copied onto the account at registration rather than read through a join, so revoking a credential can never silently _widen_ what an account it already bound is allowed to ask for.

## Configuring a client

Every client needs three things: the directory URL, the `kid`, and the HMAC key. It also needs to trust the endpoint's root certificate — see below.

**cert-manager**

```yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: simplescep
spec:
  acme:
    server: https://your-simple-scep-host/acme/<endpoint-id>/directory
    email: ops@example.com
    privateKeySecretRef:
      name: simplescep-account-key
    externalAccountBinding:
      keyID: <kid>
      keySecretRef:
        name: simplescep-eab
        key: secret
    solvers:
      - http01:
          ingress: {}
```

The `solvers` block is required by cert-manager's schema but is never exercised: the authorization is valid before cert-manager looks at it, so no solver runs.

**Caddy**

```caddyfile
{
  acme_ca https://your-simple-scep-host/acme/<endpoint-id>/directory
  acme_eab {
    key_id <kid>
    mac_key <hmac-key>
  }
}
```

**certbot**

```
certbot certonly \
  --server https://your-simple-scep-host/acme/<endpoint-id>/directory \
  --eab-kid <kid> --eab-hmac-key <hmac-key> \
  -d service.example.internal
```

**lego**

```
lego --server https://your-simple-scep-host/acme/<endpoint-id>/directory \
  --eab --kid <kid> --hmac <hmac-key> \
  --domains service.example.internal --email ops@example.com run
```

**acme.sh**

```
acme.sh --register-account --server https://your-simple-scep-host/acme/<endpoint-id>/directory \
  --eab-kid <kid> --eab-hmac-key <hmac-key>
```

### Trust comes first

The client must already trust the endpoint's root certificate, or its very first request fails TLS verification before it reaches ACME at all — and the error it reports will be about certificate verification, not about ACME, which sends people looking in the wrong place. Distribute the root the way you distribute any internal root: to the container image's trust store for cert-manager, to the OS trust store for certbot and acme.sh, to `SSL_CERT_FILE` for lego. The issuing CA's SHA-256 fingerprint is on the endpoint page for checking what you distributed.

## Issuance policy

| Setting                       | Effect                                                                                                                                                                                 |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Validity                      | How long each certificate lasts, 1 to 3650 days. Defaults to 90: ACME clients renew unattended, so a short life costs nobody anything and limits the damage from a key nobody rotates. |
| Subject pattern               | Regular expression the CSR's subject must match. Applied at finalize.                                                                                                                  |
| SAN pattern                   | Regular expression each ordered identifier must match, checked one name at a time at order time.                                                                                       |
| Permitted extended key usages | The usages every certificate issued here carries. Bounded by the issuing CA's own issuance profile; usages outside it cannot be offered.                                               |

The SAN pattern is applied when the client places its order rather than only at finalize, so a client whose configuration asks for a name you do not allow is told which name at that point — before it has generated a key — and the refusal names the identifier. That message is often the only diagnostic an unattended client leaves behind.

`ocsp_signing` and `anyExtendedKeyUsage` are permanently excluded, as they are for SCEP.

### What the CSR must contain

A finalize is refused unless the CSR asks for **exactly** the identifiers the order was authorized for — not a subset, not a superset — and unless its common name, if it sets one, is among them. This is not pedantry: certificate issuance reads the subject and SANs out of the CSR's DER verbatim, so a CSR covering a name the order never mentioned would otherwise be signed as-is. Email addresses, URIs, and `otherName` SANs are refused outright, because no order can authorize identifier types this server does not issue for.

Every client generates a conforming CSR on its own. A refusal here almost always means the client was reconfigured between placing the order and finalizing it.

## Renewal and revocation

Renewal is an ordinary new order for the same identifiers.

Revocation follows RFC 8555 §7.6. A request may be signed either by the account that ordered the certificate or by the certificate's own key, which is the way back for a client that lost its account but still holds the key it wants to disown. Holding _an_ account on the endpoint is not enough — it must be the one that ordered.

The `reason` field takes an RFC 5280 code, and only the codes this product records are accepted:

| Code | Recorded as            |
| ---- | ---------------------- |
| 0    | unspecified            |
| 1    | key_compromise         |
| 3    | affiliation_changed    |
| 4    | superseded             |
| 5    | cessation_of_operation |

Anything else is refused with `badRevocationReason` rather than quietly downgraded — a client asking for `cessationOfOperation` and silently getting `unspecified` is worse than a 400 naming the code. Revocations reach the CRL and OCSP the same way manual ones do.

**ACME Renewal Information (RFC 9773) is not implemented.** The directory omits `renewalInfo`, which is the signal that tells an ARI-capable client to fall back to its own renewal timer. Nothing needs configuring.

## Deleting an endpoint

Any endpoint can be deleted, including one that has issued certificates, but the consequences are almost all delayed — which is why the dialog enumerates them and will not proceed until the endpoint's name is typed:

- The directory URL stops responding immediately, so every configured client fails its next order.
- **Renewal fails silently.** This is the ACME-specific sting. An ACME client renews on its own timer with nobody watching, so nothing raises an alarm; the failure surfaces weeks later as a certificate expiring in production. Repoint the clients at a replacement endpoint first — and note a replacement gets a new directory URL, so it cannot stand in for this one without reconfiguring every client.
- Certificates it issued are **not revoked**. They stay valid and trusted until they expire.
- Every credential and every account registered against the endpoint is deleted, along with the order history — including the record of which orders were refused and why. The certificates themselves stay listed under Certificates.

If the aim is only to stop new enrollments, turn the endpoint off instead: reversible, immediate, and it leaves the credentials and accounts intact.

An issuing CA cannot be deleted, rotated, or deactivated while an enabled endpoint is bound to it. Turn the endpoint off first.

## Operational notes

- **Administration requires an administrator session on Standard or above.** Automation minting credentials should use a dedicated administrator session until service-account authentication is added; `POST /api/acme/endpoints/<endpoint-id>/credentials` accepts `application/json` and returns the directory URL, `kid`, and `hmac_key` for provisioning scripts.
- **Errors reach clients as RFC 8555 problem documents** (`application/problem+json`). A refused order or finalize also records its reason on the order, so a client polling afterwards is told the same thing — which is where to look when an unattended client fails.
- **`badNonce` is normal.** Clients fetch a fresh nonce and retry automatically; it appears in logs during ordinary operation and is not a fault.
- **Abandoned orders expire after seven days** and are swept hourly, along with unspent nonces older than an hour.
- Enrollment traffic is rate limited per endpoint and source address. The limit is per process, so behind a load balancer it is a courtesy rather than a control; the controls that matter — the nonce, the signature, and the credential — all live in the database.
