#!/bin/sh
set -e

export VAULT_ADDR=http://lattice-vault:8200
export VAULT_TOKEN=root

# Wait for Vault to be ready
echo "Waiting for Vault to be ready..."
until vault status >/dev/null 2>&1; do
  sleep 1
done

echo "Vault is ready. Seeding test secrets..."

# db-creds (Routes 1, 2, 3: pure env var, mixed-content env var, file mount)
vault kv put secret/vault-db-creds \
  username=admin \
  password='v@ult-s3cret'

# api-key (Route 3: file mount)
vault kv put secret/vault-api-key \
  key=vk-test-67890

# database-config (Route 5: dataFrom — all keys)
vault kv put secret/vault-database-config \
  host=db.vault-prod \
  port=5432 \
  name=vaultdb \
  ssl=true

# regcreds (Route 4: imagePullSecrets) — only if GHCR credentials are available
if [ -n "${GHCR_USER}" ] && [ -n "${GHCR_TOKEN}" ]; then
  AUTH=$(printf '%s:%s' "${GHCR_USER}" "${GHCR_TOKEN}" | base64 | tr -d '\n')
  cat > /tmp/regcreds.json <<EOFJ
{".dockerconfigjson": "{\"auths\":{\"ghcr.io\":{\"auth\":\"${AUTH}\"}}}"}
EOFJ
  vault kv put secret/vault-regcreds @/tmp/regcreds.json
  rm -f /tmp/regcreds.json
  echo "GHCR registry credentials seeded into Vault"
else
  echo "GHCR_USER/GHCR_TOKEN not set — skipping vault-regcreds (will be seeded by test code)"
fi

echo "All Vault test secrets seeded successfully!"
