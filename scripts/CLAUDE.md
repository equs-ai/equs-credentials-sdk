# scripts/

Scripts called by the release pipelines. GitHub Actions has its own set under
`.github/scripts/`.

| File | Purpose |
|------|---------|
| `release_manifest.sh` | Renders `release-manifest.yaml` for one crate's release. |

## release_manifest.sh

`release_manifest.sh <crate> [output]` — one crate per run, because each crate
releases on its own tag. The SDK's manifest is rendered by
`.github/workflows/publish-crate.yml` and by `release_manifest_job` in the
`manifest` stage; the macro crate's by
`.github/workflows/publish-common-macros.yml`.

Both workflows render with `if: always()`, so a failed publish still produces a
manifest. Every caller keeps it as a build artefact; nothing writes it to the
tag's release.

Every field comes from the checkout — no registry calls. `commit` and `tag` come
from the release build, `repo` from `Cargo.toml`'s `repository` URL (not
`CI_PROJECT_PATH`, whose namespace differs from the GitHub path the crate
advertises), and the version from `cargo metadata --no-deps`.

The digest is the sha256 of the `.crate` tarball `cargo package --locked
--no-verify` builds at this commit. Cargo stamps `.cargo_vcs_info.json` with the
commit sha, so a crate packaged at another commit hashes differently even when
its sources are identical — which is why each crate's manifest has to be
rendered by the job that publishes it. Verification is skipped because it only
rebuilds the crate; it does not change the tarball.

- `RELEASE_VERSION` sets the `release:` field, defaulting to `CI_COMMIT_TAG`.
  The macro crate's tag is `common-macros/vX.Y.Z`, so its workflow passes the
  bare version and the raw tag stays in `tag:`.
- A crate that fails to package is emitted with `digest: null` and a warning
  rather than failing the job. `cargo package` rejects a path dependency that
  carries no version requirement, so the root package's dependency on
  `equs-common-macros` has to keep its `version` field.
- `RELEASE_MANIFEST_PACKAGE_FLAGS` appends flags to `cargo package`, e.g.
  `--allow-dirty --offline` for a local run outside CI.
