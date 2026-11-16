# Releasing `sweetrust`

Releases publish from GitHub Actions, never from a laptop. `.github/workflows/release.yml` runs on a `v*` tag and publishes with npm **trusted publishing**: no npm token exists anywhere, and every tarball carries a signed provenance statement naming the commit that built it.

1. On a branch from `main`, make one commit, `release: sweetrust X.Y.Z`:
   - `packages/trust/package.json` → `"version": "X.Y.Z"`
   - `packages/trust/CHANGELOG.md` → `## [Unreleased]` becomes `## [X.Y.Z] — YYYY-MM-DD`, plus a compare link at the bottom
   - `packages/trust/README.md` § *Status* → names the current version
2. Open a pull request; merge it when CI is green.
3. Tag the merge commit with an annotated tag and push it:
   `git tag -a vX.Y.Z <merge-sha> -m "sweetrust X.Y.Z" && git push origin vX.Y.Z`
4. The release workflow checks the tag against `package.json`, re-runs the gates (`prepublishOnly`) and publishes.
5. Check: `npm view sweetrust@X.Y.Z` and the provenance badge on npmjs.com.

If the publish step fails after the tag exists, fix the cause and re-run it with **Actions → release → Run workflow** and the same tag. Never move a tag that has been published.

One-time setup (done on npmjs.com by the package owner): package settings → Trusted Publisher → GitHub Actions, repository `sweeai/sweetrust`, workflow `release.yml`.

## Releasing `sweetrust-sui`

The same steps, with the adapter's files and its own tag namespace. `.github/workflows/release-sui.yml` runs on a `sweetrust-sui@*` tag, which never matches `v*`, so a tag can publish only the package it names.

1. On a branch from `main`, make one commit, `release: sweetrust-sui X.Y.Z`: `packages/sui/package.json`, `packages/sui/CHANGELOG.md` (with a link at the bottom) and `packages/sui/README.md` § *Status*, as above. If the release needs a newer kernel, raise the `sweetrust` peer range in the same commit, and release the kernel first.
2. Open a pull request; merge it when CI is green.
3. `git tag -a sweetrust-sui@X.Y.Z <merge-sha> -m "sweetrust-sui X.Y.Z" && git push origin sweetrust-sui@X.Y.Z`
4. The workflow checks the tag against `packages/sui/package.json`, builds the kernel, re-runs the adapter's gates (`prepublishOnly`) and **stages** the version: it is on npm but nobody can install it yet.
5. A maintainer approves it with 2FA: `npm stage list sweetrust-sui`, then `npm stage view <stage-id>`, then `npm stage approve <stage-id>` (or npmjs.com → account settings → **Staged Packages** → Approve). Approval is the release. To refuse a staged version instead, `npm stage reject <stage-id>`.
6. Check: `npm view sweetrust-sui@X.Y.Z` and the provenance badge on npmjs.com.

The trusted publisher for `sweetrust-sui` allows `npm stage publish` only ("Allow npm publish" unticked), as `npm help stage` advises. Staging needs npm ≥ 11.15.0.

**Set up once, 2026-11-15.** The name was claimed with a code-less `0.0.1` (as `sweetrust` was before 0.4.0), so npmjs.com could offer the Trusted Publisher form: GitHub Actions, organization `sweeai`, repository `sweetrust`, workflow `release-sui.yml`, no environment, both "Allow" boxes unticked. A new trusted publisher must complete its first publish within two days or it expires, so the first release is staged and approved in the same sitting the publisher is saved.
