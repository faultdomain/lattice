# Home Media Server Stack

A complete home media server using Lattice's service mesh with bilateral agreements.

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

## Shared Volumes

For hardlinking to work (saving disk space), services share volumes:

- `/downloads` - Shared between NZBGet and Sonarr
- `/media` - Shared between Sonarr and Jellyfin

## Deploy

```bash
kubectl apply -k examples/media-server/
```

## Access

After deployment, access via ingress:

- Jellyfin: https://jellyfin.home.local
- Sonarr: https://sonarr.home.local

Configure your DNS or /etc/hosts to point these to your cluster's ingress IP.
