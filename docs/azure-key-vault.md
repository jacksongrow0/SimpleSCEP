# Azure Key Vault

SimpleSCEP can create and use software- or HSM-protected CA signing keys in Azure Key Vault. Set `KEY_PROVIDER=azure`; administrators choose software or HSM protection independently when creating each CA.

## Vault and keys

Software-protected CAs work with a Standard or Premium vault and create `EC` or `RSA` signing keys. HSM-protected CAs require a Premium vault and create `EC-HSM` or `RSA-HSM` keys. SimpleSCEP marks generated keys non-exportable and grants them only `sign` and `verify` operations.

Create one RSA or RSA-HSM protection key before starting SimpleSCEP. It wraps per-record AES-256 keys used to encrypt TOTP secrets, SCEP RA private keys, and ACME EAB material. This key is independent of each CA's protection selection:

```sh
az keyvault key create \
  --vault-name example \
  --name simplescep-protection \
  --kty RSA-HSM \
  --size 3072 \
  --ops wrapKey unwrapKey
```

Configure its full, versioned key ID—not merely its name:

```text
KEY_PROVIDER=azure
AZURE_KEY_VAULT_URL=https://example.vault.azure.net
AZURE_KEY_VAULT_PROTECTION_KEY=https://example.vault.azure.net/keys/simplescep-protection/<version>
```

Changing the protection-key version makes existing encrypted records unreadable. Rotation therefore requires a re-encryption migration; do not edit this value on a running installation.

## Authentication and authorization

The application uses the Azure SDK `DefaultAzureCredential`. Prefer a managed identity when SimpleSCEP runs in Azure. For an external deployment, configure a dedicated service principal through `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET`.

The identity needs data-plane permissions to:

- create, read, attest, and delete CA keys;
- sign digests with CA keys; and
- wrap and unwrap keys with the configured protection key.

The built-in **Key Vault Crypto Officer** role supplies the required key-management and cryptographic permissions. A custom role can narrow access to the corresponding create, get, delete, sign, wrap, unwrap, and attestation actions. Scope the assignment to the dedicated vault and enable soft delete and purge protection.

## Encryption format

Azure Key Vault RSA-OAEP-256 wraps a fresh AES-256 key for each protected database value. AES-GCM encrypts the value locally with its purpose as authenticated data. The stored envelope records the immutable Azure protection-key version, wrapped AES key, nonce, and ciphertext. Neither CA private keys nor the configured protection key leave Key Vault.

## Existing CA import

The first Azure release does not expose SimpleSCEP's existing wrapped-key CA import wizard. Azure HSM BYOK uses a provider-specific transfer-blob ceremony rather than Google Cloud KMS import jobs. Create new CAs in SimpleSCEP when using Azure Key Vault; deployments that require the current browser-based wrapped-key import workflow must use Google Cloud KMS.
