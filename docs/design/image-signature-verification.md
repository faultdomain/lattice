# Image Signature Verification

## Problem

Any compromised registry, supply chain attack, or misconfigured pipeline can push unsigned or tampered images into a cluster. Lattice currently passes container images through to Kubernetes without verifying their provenance. There is no way to enforce that workloads only run images signed by trusted parties.

## Goals

- Verify container image signatures before workloads are admitted
- Default-deny: unsigned images are rejected unless a Cedar policy explicitly allows them
- Support cosign (keyless and key-based) as the verification backend
- Integrate with the existing Cedar authorization model so platform teams can grant exemptions per-namespace, per-service, or per-registry
- No new CRDs unless necessary — extend existing types where possible

## Non-Goals

- Runtime re-verification (out of scope; this is admission-time only)
- Notary v1 support (deprecated; cosign/sigstore is the standard)
- SBOM or SLSA attestation verification (future work, designed for but not implemented)

---

## Design

### Trust Policy: ImageTrustPolicy on ImageProvider

Image verification policy is configured on the `ImageProvider` CRD. This is the natural home because ImageProvider already represents a registry relationship (credentials, hostname, scope). Adding trust policy here means: "for images from this registry, here is how we verify them."

```yaml
apiVersion: lattice.dev/v1alpha1
kind: ImageProvider
metadata:
  name: ghcr-production
  namespace: lattice-system
spec:
  providerType: GHCR
  registry: ghcr.io/acme
  credentials:
    provider: vault-prod
    remoteKey: registry/ghcr-token
  trust:
    # Require signatures by default. Cedar can override per-service.
    enforce: true
    # Cosign verification authorities (at least one must match)
    authorities:
      - name: release-key
        key:
          # ESO-backed secret containing the cosign public key
          provider: vault-prod
          remoteKey: signing/cosign-release.pub
      - name: ci-keyless
        keyless:
          issuer: https://token.actions.githubusercontent.com
          subject: https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main
```

Fields:

| Field | Type | Description |
|-------|------|-------------|
| `trust.enforce` | `bool` | When true, images from this registry must be signed. Default: `true`. |
| `trust.authorities` | `Vec<VerificationAuthority>` | Ordered list of accepted signers. Image is trusted if ANY authority matches. |
| `authority.key` | `CredentialSpec` | ESO-backed public key (PEM). Uses existing credential infrastructure. |
| `authority.keyless` | `KeylessConfig` | Sigstore keyless verification (OIDC issuer + subject match). |

When `trust.enforce` is true and no authority matches, the image is rejected. When `trust.enforce` is false, verification is skipped (for dev registries, mirrors, etc).

### Cedar Authorization: SkipImageVerification

The existing Cedar model extends with one new action and one new resource type:

```
Action:    Lattice::Action::"SkipImageVerification"
Resource:  Lattice::ImageRef::"ghcr.io/acme/debug-tools:latest"
  attrs: { registry: "ghcr.io/acme", name: "debug-tools", tag: "latest" }
```

Default behavior is **deny** — if an ImageProvider has `trust.enforce: true` and the image has no valid signature, the workload is rejected. A Cedar `permit` policy on `SkipImageVerification` overrides this for specific services or images.

Example policies:

```cedar
// Allow the debug namespace to skip verification (dev tooling)
permit(
    principal is Lattice::Service,
    action == Lattice::Action::"SkipImageVerification",
    resource
) when {
    principal.namespace == "debug"
};

// Allow a specific unverified base image used during migration
permit(
    principal,
    action == Lattice::Action::"SkipImageVerification",
    resource == Lattice::ImageRef::"docker.io/library/redis:7-alpine"
);

// Block a known-compromised image even if other policies would allow it
forbid(
    principal,
    action == Lattice::Action::"SkipImageVerification",
    resource == Lattice::ImageRef::"ghcr.io/acme/app:v2.3.1"
);
```

This follows the same pattern as `AccessSecret`, `OverrideSecurity`, and `AccessExternalEndpoint` — default-deny with Cedar overrides.

### Verification Flow

Verification happens during workload compilation, not at admission webhook time. This is consistent with how Lattice handles secrets (Cedar auth during compile) and mesh policy (graph evaluation during compile). The webhook validates structural correctness; the compiler enforces policy.

```
LatticeService created/updated
    |
    v
ServiceCompiler::compile()
    |
    v
WorkloadCompiler::compile()
    |-- authorize_secrets()      (existing)
    |-- authorize_volumes()      (existing)
    |-- authorize_security()     (existing)
    |-- verify_images()          (NEW)
    |       |
    |       |-- For each container image:
    |       |     1. Find matching ImageProvider by registry prefix
    |       |     2. If no provider or trust.enforce == false: pass
    |       |     3. Resolve image to digest (HEAD to registry)
    |       |     4. Verify signature against each authority
    |       |     5. If no signature matches:
    |       |        a. Check Cedar: SkipImageVerification for this service + image
    |       |        b. If Cedar permits: pass (log warning)
    |       |        c. If Cedar denies: fail compilation
    |       |
    |-- render_containers()      (existing)
    v
CompiledWorkload (or error)
```

On verification failure, the service enters `Failed` phase with a message like:
```
Image ghcr.io/acme/app:v2.3.1 has no valid signature from any trusted authority.
Cedar policy does not permit SkipImageVerification for payments/checkout.
```

### Cosign Integration

Cosign runs as a subprocess, not as a Rust library. The `sigstore-rs` crate conflicts with `aws-lc-rs` (FIPS) due to its dependency on `ring`. Until sigstore-rs supports pluggable crypto backends, subprocess is the only FIPS-compatible path.

```rust
/// Verify an image signature using cosign CLI.
///
/// Returns Ok(true) if signature is valid, Ok(false) if no signature found,
/// Err on verification failure or cosign not available.
async fn cosign_verify(
    image_ref: &str,   // must include digest: "ghcr.io/acme/app@sha256:abc..."
    authority: &VerificationAuthority,
) -> Result<bool, ImageVerifyError>
```

For key-based verification:
```bash
cosign verify --key /tmp/key.pub ghcr.io/acme/app@sha256:abc...
```

For keyless verification:
```bash
cosign verify \
  --certificate-identity "https://github.com/acme/app/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/acme/app@sha256:abc...
```

The cosign binary is included in the operator Docker image (already built from source in the Dockerfile's Go builder stage for FIPS compliance with Go 1.25 native FIPS).

### Digest Pinning

When verification succeeds, the compiler rewrites the image reference to use the verified digest:

```
Input:  ghcr.io/acme/app:v2.3.1
Verify: ghcr.io/acme/app:v2.3.1 → resolves to sha256:abc123...
Output: ghcr.io/acme/app@sha256:abc123...
```

This prevents TOCTOU attacks where a tag is re-pushed between verification and pod creation. The pod spec always references the exact digest that was verified.

### Key Management

Cosign public keys are stored as ESO-backed secrets using the existing `CredentialSpec` infrastructure. No new secret management is needed.

```yaml
trust:
  authorities:
    - name: release-key
      key:
        provider: vault-prod           # existing SecretProvider
        remoteKey: signing/cosign.pub  # path in Vault
```

The ImageProvider controller resolves the key via ESO before verification. Key rotation is handled by updating the Vault secret — ESO syncs it, the next compilation picks up the new key.

### Caching

Image digest resolution and signature verification are expensive (network calls to the registry). Results are cached:

- **Digest cache**: `image:tag` -> `sha256:...`, TTL 5 minutes. Invalidated on ImageProvider spec change.
- **Signature cache**: `sha256:...` + authority hash -> `verified: bool`, TTL 1 hour. Invalidated on authority key rotation.

Cache is in-memory (`moka` concurrent cache, already a dependency). No persistence needed — cold start re-verifies, which is correct.

### Status Reporting

Verification results are visible in the LatticeService status:

```yaml
status:
  phase: Ready
  imageVerification:
    - image: ghcr.io/acme/app@sha256:abc123...
      verified: true
      authority: release-key
      verifiedAt: "2026-04-11T10:00:00Z"
    - image: docker.io/library/redis:7-alpine
      verified: false
      skipped: true
      reason: "Cedar policy permits SkipImageVerification"
```

### Error Handling

| Scenario | Behavior |
|----------|----------|
| No ImageProvider matches registry | Pass (no policy to enforce) |
| ImageProvider has `trust.enforce: false` | Pass (verification disabled) |
| Registry unreachable during digest resolution | Fail compilation (no silent fallback) |
| Cosign binary not found | Fail compilation (operator misconfigured) |
| Signature invalid | Fail unless Cedar permits skip |
| Key expired or revoked | Fail (cosign handles this) |
| Multiple authorities, one matches | Pass (any match is sufficient) |
| Multiple authorities, none match | Fail unless Cedar permits skip |

No silent fallbacks. If verification is enforced and can't be performed, the workload fails loudly.

---

## Implementation Plan

### Phase 1: ImageProvider trust policy + cosign subprocess

1. Add `TrustPolicy` and `VerificationAuthority` types to `lattice-crd`
2. Add `SkipImageVerification` action and `ImageRef` resource to Cedar entity model
3. Implement `CosignVerifier` in `lattice-workload` (subprocess wrapper)
4. Add `verify_images()` stage to `WorkloadCompiler`
5. Add cosign binary to Dockerfile (Go builder stage)
6. Add `imageVerification` to LatticeService status
7. Unit tests for verifier, Cedar integration tests for skip policy

### Phase 2: Digest pinning + caching

1. Implement digest resolution via registry API (HEAD request)
2. Rewrite image refs to digests in compiled pod template
3. Add moka cache for digest + signature results
4. Integration tests for tag-to-digest rewriting

### Phase 3: Keyless verification

1. Implement keyless authority config (issuer + subject)
2. Pass OIDC parameters to cosign subprocess
3. E2E test with GitHub Actions OIDC token

### Future: Attestation verification

The `VerificationAuthority` type is designed to extend with attestation policies:

```yaml
authorities:
  - name: slsa-build
    attestation:
      type: https://slsa.dev/provenance/v1
      predicateType: https://slsa.dev/provenance/v1
      conditions:
        - field: buildType
          equals: https://github.com/slsa-framework/slsa-github-generator
```

This is not implemented in Phase 1-3 but the type structure accommodates it.
