# Mihomo runtime

Monitor expects two deployment artifacts in this directory:

- `mihomo.exe` — the pinned Windows Mihomo executable;
- `mihomo.sha256` — its lowercase SHA-256 digest, optionally followed by the
  filename.

Both files are intentionally tracked in Git. A commit therefore binds Monitor
to one exact Mihomo executable, and public publication must read both files from
the selected Git source ref rather than from the working tree. Monitor refuses
to start a VPN probe if either artifact is missing or if the digest does not
match.

Current verified development runtime:

- release: `v1.19.30` (`windows amd64`, Go `1.26.6`);
- official archive:
  `mihomo-windows-amd64-v1.19.30.zip`;
- official archive SHA-256:
  `22c09fd67673895ef7cd6b1820563918275c3d316f2462b306208675118db3c0`;
- extracted `mihomo.exe` SHA-256:
  `f55b3028d9160beb9044f21b05dd7405b46524614a19642d6291492f5f985761`.

Corresponding source: <https://github.com/MetaCubeX/mihomo/tree/v1.19.30>.
The authoritative artifact provenance and license metadata are recorded in
`supply_chain/assets.json`; the bundled GPL-3.0 license text is stored at
`supply_chain/licenses/mihomo-GPL-3.0.txt`.
