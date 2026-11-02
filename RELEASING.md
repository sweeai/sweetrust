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
