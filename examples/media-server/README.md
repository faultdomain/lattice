# Home Media Server Stack

A complete home media server using Lattice's service mesh with bilateral agreements and shared volumes.

## Services

| Service | Port | Description |
|---------|------|-------------|
| Jellyfin | 8096 | Media streaming server |
| NZBGet | 6789 | Usenet downloader |
| Sonarr | 8989 | TV show automation |

## Architecture

```
                    ┌─────────────────┐
                    │    Internet     │
                    └────────┬────────┘
                             │ ingress
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              │
         ┌────────┐    ┌──────────┐         │
         │Jellyfin│    │  Sonarr  │◄────────┘
         │ :8096  │    │  :8989   │
         └────┬───┘    └────┬─────┘
              │             │
              │    ┌────────┴────────┐
              │    │                 │
              │    ▼                 ▼
              │ ┌──────┐       ┌─────────┐
              └─│NZBGet│       │ Indexers│
                │:6789 │       │(external)
                └──────┘       └─────────┘
```

## Bilateral Agreements (Dependency Graph)

Traffic is only allowed when BOTH sides agree:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Dependency Graph                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Sonarr                    NZBGet                              │
│   ┌──────────────┐          ┌──────────────┐                    │
│   │ resources:   │          │ resources:   │                    │
│   │   nzbget:    │─────────▶│   sonarr:    │                    │
│   │     outbound │  MATCH!  │     inbound  │                    │
│   └──────────────┘          └──────────────┘                    │
│                                                                 │
│   Sonarr                    Jellyfin                            │
│   ┌──────────────┐          ┌──────────────┐                    │
│   │ resources:   │          │ resources:   │                    │
│   │   jellyfin:  │─────────▶│   sonarr:    │                    │
│   │     outbound │  MATCH!  │     inbound  │                    │
│   └──────────────┘          └──────────────┘                    │
│                                                                 │
│   NZBGet ──X──▶ Sonarr     (no outbound declared = DENIED)      │
│   Jellyfin ──X──▶ NZBGet   (no bilateral agreement = DENIED)    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### L7 Policies Applied

| Route | Retries | Timeout | Rate Limit |
|-------|---------|---------|------------|
| Sonarr → NZBGet | 3 attempts, 5xx/connect-failure | 30s | - |
| Sonarr → Jellyfin | - | 60s | - |
| * → NZBGet | - | - | 1000/min |
| * → Jellyfin | - | - | 100/min |

## Shared Volumes (Score-compatible)

Volumes are shared using the Score-native `id` field:

- **Owner** (has `size`): Creates and owns the PVC
- **Reference** (no `size`, just `id`): Uses existing PVC

```
┌─────────────────────────────────────────────────────────────────┐
│                    Volume Ownership                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   NZBGet (OWNER)                   Sonarr (REFERENCE)           │
│   ┌────────────────────┐           ┌────────────────────┐       │
│   │ downloads:         │           │ downloads:         │       │
│   │   type: volume     │           │   type: volume     │       │
│   │   id: media-       │◄──shares──│   id: media-       │       │
│   │       downloads    │           │       downloads    │       │
│   │   params:          │           │   # no params =    │       │
│   │     size: 500Gi    │           │   # reference      │       │
│   └────────────────────┘           └────────────────────┘       │
│                                                                 │
│   Jellyfin (OWNER)                 Sonarr (REFERENCE)           │
│   ┌────────────────────┐           ┌────────────────────┐       │
│   │ media:             │           │ media:             │       │
│   │   type: volume     │           │   type: volume     │       │
│   │   id: media-       │◄──shares──│   id: media-       │       │
│   │       library      │           │       library      │       │
│   │   params:          │           │   # no params      │       │
│   │     size: 1Ti      │           └────────────────────┘       │
│   └────────────────────┘                                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### PVC Naming

| Volume | ID | PVC Name |
|--------|-----|----------|
| NZBGet config | (none) | `nzbget-config` |
| NZBGet downloads | `media-downloads` | `vol-media-downloads` |
| Jellyfin media | `media-library` | `vol-media-library` |
| Sonarr downloads | `media-downloads` | `vol-media-downloads` (shared) |

This enables:
- **Hardlinking**: Sonarr can hardlink completed downloads to media library
- **Instant moves**: No copying needed when moving files between services
- **Disk efficiency**: Single copy of files shared between services

## Deploy

```bash
kubectl apply -k examples/media-server/
```

## Access

After deployment, access via ingress:

- Jellyfin: https://jellyfin.home.local
- Sonarr: https://sonarr.home.local

Configure your DNS or /etc/hosts to point these to your cluster's ingress IP.
