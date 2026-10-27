# Release Process

1. Build with `./scripts/build.sh`; keep `logs/build.log`.
2. Run `./scripts/test_boot.sh`; keep `logs/serial.log` and the test report.
3. Fix failures, rebuild, retest. Never package a failed build as stable.
4. Tag the exact source in git (`vX.Y.Z`) only after the test passes.
5. Create `archives/code/nxtsOS-vX.Y.Z-source.tar.gz` (source + docs +
   scripts + tests + manifest, no build outputs, no secrets).
6. Create `archives/dist/nxtsOS-vX.Y.Z-dist.zip` (ISO + launch scripts +
   VM guide + manifest + test report + checksums).
7. Generate SHA-256 checksums and verify them by re-hashing the archives.
8. Write `releases/vX.Y.Z/` manifest + test report + `SHA256SUMS`.
9. Remote publishing only with explicit authorisation, to a repository
   that does not overwrite unrelated work; prefer private initially.
   If no account is connected/authorised, record that instead of claiming
   a push.
10. Update `CHANGELOG.md` and `docs/PROJECT_STATUS.md`.
