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
4. The workflow checks the tag against `packages/sui/package.json`, builds the kernel, re-runs the adapter's gates (`prepublishOnly`) and publishes.
5. Check: `npm view sweetrust-sui@X.Y.Z` and the provenance badge on npmjs.com.

**Before the first release, once.** A trusted publisher is set on the package's own settings page on npmjs.com, so the package must exist before one can be added, and the name is claimed first by a placeholder with no code, as `sweetrust` was (0.0.1, before 0.4.0). The package owner, logged in to npm on their own machine, publishes a directory holding only a `package.json` (`"name": "sweetrust-sui"`, `"version": "0.0.1"`, `"license": "Apache-2.0"`, a description saying it is a name placeholder) and a one-line README, with `--access public`. Then, on npmjs.com: package settings → Trusted Publisher → GitHub Actions, repository `sweeai/sweetrust`, workflow `release-sui.yml`. A new trusted publisher must complete a publish within two days or it expires, so tag the release soon after.
