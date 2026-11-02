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

## WRP-BACKUP-20261102-001

- Completed: 2026-11-02 05:17:44 MSK.
- Status: installed, delivered, restored and scheduled.
- Deployed controller/helper code commit: `e25c21dac33bcb34c1bc399aacf93275923a7eb8`, pushed and verified against the upstream before installation.
- Installed controller SHA-256: `72fbbd92006836eece02236f1087af1e8cc1de7c8495245d30f817d2bc7b2a4e`.
- Installed helper SHA-256: `18ad5ac00fe5a3c8f03dfc465484f02663a0e48f110f0b5bc005262461dc1aa6`, matching the file actually executed in the helper image.
- Helper image ID: `sha256:3792e99415f60f0a8a46ffac28875631660fa0904febe5cb5c63ba935d1b5a7f`; Python 3.12 and py7zr 1.0.0. Encryption helpers are ephemeral, have no network, and are limited to one CPU and 1 GiB RAM.
- Scope: consistent SQL dump and required panel runtime settings, dedicated Nginx virtual host, only that host's TLS chain/key and renewal settings, plus restore manifest. Other projects, the shared ACME account, backup encryption password and Telegram credentials are excluded from the payload.
- Snapshot consistency: exported PostgreSQL repeatable-read snapshot used by pg_dump; validation table counts came from that same source transaction, not a later live database.
- First archive: `warp-db-20261102-050825.7z`, 12,178,973 bytes, SHA-256 `000c5a98d8f6b2c88500e7b2e369c64094cfee0792d887785d767a9bd9837f04`.
- Validation: encrypted headers require a password; all payload files passed encryption/extraction round-trip hashes; actual Telegram document was downloaded and reassembled with an identical whole-archive SHA-256. A separate network-isolated PostgreSQL container restored the downloaded copy successfully, with all table counts matching the original snapshot.
- Independent coordinator validation downloaded the delivered document from another computer and confirmed the same size and SHA-256.
- Delivery: documents only, no caption, silent mode, owner-selected destination/topic. Recipient and delivery identifiers remain only in the private receipt and runtime configuration.
- Files larger than 16 MiB are split into numbered documents, downloaded and reassembled with the original checksum. Small-threshold split/reassembly tests passed.
- Retention: latest 72 fully verified delivered archive groups belonging to this installation. Unsent archives, foreign installation records, unrelated files and symlink receipts are preserved. Three focused retention/split/symlink tests passed.
- Scheduling: hourly Europe/Moscow timer, up to 20 seconds jitter, persistent catch-up, cross-process flock. The first-run restore-test override was removed before enabling the timer. Next trigger at enable: 2026-11-02 06:00:09 MSK.
- Security checks: private temporary/archive directories 0700, secret runtime configuration 0600, passwords supplied to the encryption helper only through stdin, safe error paths tested with sentinel secrets. No plaintext temporary payload remained after the first run.
- Operational checks: simultaneous manual invocation was skipped by the lock; backup service completed with status 0; timer is enabled and active. Panel, database, web generator, bot and analyzer remained healthy without application container replacement.
- Approval: owner explicitly authorized the new hourly panel backup job, encrypted offsite delivery to the selected Telegram topic, and protected credential storage. No new user-facing recovery text or Telegram caption was added.
