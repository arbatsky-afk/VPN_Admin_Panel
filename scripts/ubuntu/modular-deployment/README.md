# Modular deployment bundle

This bundle contains the server-side implementation of the modular deployment.
The Windows launcher uploads it to a unique `/root/.vpn-deploy-<id>` staging
directory, verifies a generated SHA-256 manifest, runs one installer, and then
removes the staging directory. The bundle and generated `config.env` are not
kept permanently on the server.

Python loads strict tracked `app/defaults.json` and creates immutable Component
inputs. The PowerShell launcher receives those inputs and never reads the
defaults resource or legacy deployment configuration itself.

## Layout

- `.gitattributes` — enforces LF for tracked bundle text without classifying
  binary component assets as text.
- generated `config.env` — exists only in protected temporary staging; for
  Netdata it temporarily includes the claim token and is removed on every exit.
- `lib/common.sh` — validation and shared shell helpers.
- `lib/state.sh` — legacy Base + Security marker compatibility and the shared
  component State registry under `/opt/vpn/state/components.json`.
- `lib/firewall.sh` — firewall paths and the validate-before-apply operation.
- `lib/port_contract.py` — bounded cryptographic first-install allocation and
  strict config/recovery/fragment/active-ruleset/listener verification.
- `assets/` — component-local pinned archives, declarations and checksums.

Component installers are added only with their own vertical slices. Base +
Security, Xray, Hysteria2, Mieru, Docker, and Nginx are implemented and connected to
the PowerShell modular launcher and the Deploy UI.

Base + Security, Docker, Mieru, and Nginx run apt/dpkg mutations through the shared
package-manager wrapper. It does not wait or retry when another package
operation owns the lock. A confirmed lock conflict fails immediately with:
`The system package manager is currently busy with another operation. Try this
deployment again later.` Other package-manager errors retain their original
diagnostics and exit status.

Xray, Hysteria2, and Mieru allocate a port only when their recovery metadata is
absent. The tracked policy ranges are respectively `10000-16999/TCP`,
`17000-23999/UDP`, and `24000-30999/TCP|UDP`. An installed component always
reuses its validated recovery port, even when a user changed it outside the
initial range. A successful installer emits one `VPN_ADMIN_DEPLOY_RESULT`
marker only after strict runtime verification; the Windows launcher stores that
confirmed result only for the operation outcome and does not create a local
per-server cache.

## Nginx static site

`nginx` is available after Base + Security and uses fixed `80/tcp` and
`443/tcp`. The Deploy input selects the desired final self-signed TLS state or
Let's Encrypt state with a validated domain. Every valid request is applied,
including Let's Encrypt to self-signed downgrade and direct Let's Encrypt domain
replacement. The installer stages and validates the requested certificate and
vhost, verifies the exact managed runtime, and restores the previous managed
files, TLS material, renewal runtime, firewall and service state on failure.
Let's Encrypt errors never trigger a self-signed fallback. Management exposes
read-only HTTP/HTTPS health, server/TLS metadata and certificate expiry.
Backup/Restore owns the complete managed vhost, TLS state and material, site
content and Nginx firewall fragment.

## Firewall ownership

The Base + Security component owns the main nftables configuration and its own
fragment. Components that need inbound firewall rules own only their fixed
fragment paths:

```text
/etc/nftables.d/20-xray.nft
/etc/nftables.d/30-hysteria2.nft
/etc/nftables.d/40-mieru.nft
/etc/nftables.d/50-nginx.nft
```

Every component must call `apply_firewall` after changing its fragment. That
function validates the complete configuration before it asks systemd to load
it. No modular script may use `flush ruleset`.
