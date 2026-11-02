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

## WRP-20261102-001

- Completed: 2026-11-02 04:20:13 MSK.
- Status: restored and verified.
- Configuration commit: `e68dc8a3f9082b1c373b2cf5d50279d7d058535b`, pushed to the current upstream.
- Application image: `ghcr.io/openwarpkit/warp-relay-panel@sha256:8a05c2bbc378fc30836292ddb0338c1c0c9cf0b5dd0d19a78793e437a1084292`.
- Application source files match the existing main checkout after line-ending normalization. The application code was unchanged.
- Source archive: `warp-db-20261101-190020.7z`, SHA-256 `f515d8f7ec5769f7c5d8eb08c05cf7332d7721352021bc534f2c0c22dacd5b83`.
- SQL artifact SHA-256: `83fbfa086958187ba3e434dbf6fa3a1f4ff3bb007cef0050e500ec2f8f67a8ef`.
- Snapshot: 2026-11-01 19:00:20 MSK. The latest activation is 16:00:15 UTC. All 98,460 encrypted values were decrypted successfully with the preserved key.
- Restore validation: isolated PostgreSQL with no external network; 11,474 clients, 81,674 activation records, 50 rate limits and 11 relay records. Verified restored dump SHA-256: `5d88758fac6cf7ee175451c339b9997e1e269b021ce714a3e9461218e7f8df8b`.
- Runtime: private WireGuard bind, preserved API/encryption keys, PostgreSQL volume retained across container replacement, automatic reconcile every 60 seconds.
- Reconciliation: only two bot relay credential pairs were absent from the restored snapshot. They were cleared transactionally with an exact-row export and conditional rollback. No user accounts or unrelated fields were removed.
- The current client count was 11,462 at verification. The 12 removed snapshot IDs exactly match the bot's preexisting pending-deletion queue, which resumed normal processing after API recovery. Those records were not part of the two-row credential cleanup.
- Relay validation: all 11 agents healthy, all eight full agents synchronized, three min agents healthy, reconcile reported `changed=0 failed=0`.
- Routing validation: direct HTTPS API and existing public activation proxy returned HTTP 200 with database health OK. API requests without a key were rejected. TLS verification remained enabled.
- Backups: original SQL, verified restored dump, full pre-change bot database dump, exact affected bot rows, agent state and configuration snapshots were retained privately. No database contents, credentials or private keys are included in Git.
- Approval: owner request in this chat to restore the specified archive on the specified server, reconcile absent bot credentials and switch the proxy; subsequent explicit instruction to move the API A record. DNS change was applied by the coordinating agent and independently verified.
