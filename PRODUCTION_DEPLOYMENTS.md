# Production deployments

## WRP-20261027-001

- Completed: 2026-10-27 09:56:30 Europe/Moscow.
- Result: one approved full relay updated from v2.2.20 to v2.2.21 through the existing panel self-update API. Other agents and the panel were excluded.
- Repository: `https://github.com/openwarpkit/warp-relay-panel.git`.
- Code commit and verified checkout: `df0001a702cbeaeee0b5720d689c190a6673d6f0`.
- Release: [agent-v2.2.21](https://github.com/openwarpkit/warp-relay-panel/releases/tag/agent-v2.2.21).
- Asset: `warp-relay-agent`.
- Installed asset SHA256: `b3ec1e78617db7cacb40056284c88085d0b0e46f79252e89aaa181ccf0c28172`, matching the published release asset.
- Maintenance: checkout ownership changed from root to the service account `nobody:nogroup`. Git operations succeed under the service account. No global Git trust exception was added.
- Download recovery: a TLS handshake timeout to the release asset endpoints was reproduced with the normal socket MSS. A socket MSS of 1200 succeeded with certificate verification. Four temporary host routes with MTU 1240 and advertised MSS 1200 allowed the existing updater to download the release.
- Cleanup: all four temporary routes were removed after verification and their automatic cleanup timer was stopped. Interface MTU and persistent network configuration were not changed.
- Runtime checks: health reports v2.2.21; `last_update.ok=true`; systemd service is active; the monthly traffic counter increased from `13469152185774` to `13470920285427` bytes without a reset.
- Remaining limitation: the release asset path MTU issue was not permanently repaired. Future downloads can require the same temporary workaround or a separately approved network fix.
- Approval: [owner reply in this chat](codex://threads/01a16c6f-5f3f-78a0-941f-991fbe9a5f2d), 2026-10-27, "Разрешаю SSH и обновление этого relay", following the exact single-relay scope and full code SHA in the approval question.
