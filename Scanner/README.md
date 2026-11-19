# SafeBrowse Dynamic Webpage Scanner (Docker + Playwright)

Isolated browser-based dynamic analysis worker for SafeBrowse. Evaluates JavaScript-rendered pages inside a disposable, hardened Linux container and passes the bounded post-load DOM to **AI 2 (`model_content.joblib`)** without changing AI 2's 38-feature contract.

## Build Image
```bash
cd Scanner
docker build -t safebrowse-scanner:latest .
```

## Security Controls Applied Per Job
- Disposable `--rm` container per scan, always force-removed in `finally` on timeout/crash.
- Non-root `pwuser`, `--cap-drop=ALL`, `--security-opt=no-new-privileges:true`, `--read-only` rootfs with bounded `tmpfs`.
- Resource limits: `--memory=1024m`, `--cpus=1.0`, `--pids-limit=128`, `--ipc=private`.
- No host filesystem mounts, no Docker socket, no secrets, no persistent browser profile.
- SSRF defense-in-depth: pre-flight URL/DNS validation + Playwright route interception blocking non-public IPv4/IPv6 ranges on all redirects and subrequests.

## Configuration (Backend Environment Variables)
- `DYNAMIC_SCANNER_IMAGE` (default `safebrowse-scanner:latest`)
- `DYNAMIC_SCANNER_TIMEOUT_S` (default `35`)
- `DYNAMIC_SCANNER_CONCURRENCY` (default `2`)

## Residual Risks & Production Hardening
Docker shares the host kernel. For public untrusted workloads, run behind an explicit egress firewall/proxy blocking internal/cloud-metadata CIDRs at the network layer, and consider gVisor (`runsc`) or microVM isolation.

## Rollback
1. Remove the `DynamicScanCard` usage from `DesktopApp/src/pages/user/scan/DetailedAnalysis.tsx`.
2. Remove the `/scans/<id>/dynamic` routes from `Backend/web/controllers/scans.py`.
3. Drop `public.dynamic_scans` if desired (`DROP TABLE IF EXISTS public.dynamic_scans;`).
