# Releasing `sweetrust`

Releases go out from GitHub Actions, never from a laptop, and a person approves twice: once on GitHub (the `release` environment) and once on npm (a staged version). `.github/workflows/release.yml` runs on a `v*` tag and **stages** the version; it never publishes one. No npm token exists anywhere, and every tarball carries a signed provenance statement naming the commit that built it.

The workflow has two jobs. `build` installs dependencies, runs the package's gates, packs the tarball and records its integrity in the run summary; it has no way to ask for the registry login token. `stage` downloads that tarball, checks it is the one `build` packed, and stages it; it installs and builds nothing, and it is the only job that can ask for the token. The integrity check proves the file was not swapped between the two jobs; it does not prove the build was clean.

1. On a branch from `main`, make one commit, `release: sweetrust X.Y.Z`:
   - `packages/trust/package.json` → `"version": "X.Y.Z"`
   - `packages/trust/CHANGELOG.md` → `## [Unreleased]` becomes `## [X.Y.Z] — YYYY-MM-DD`, plus a compare link at the bottom
   - `packages/trust/README.md` § *Status* → names the current version
2. Open a pull request; merge it when CI is green.
3. Tag the merge commit with an annotated tag and push it:
   `git tag -a vX.Y.Z <merge-sha> -m "sweetrust X.Y.Z" && git push origin vX.Y.Z`
4. The `build` job runs, then the `stage` job stops at **Waiting for review**. Open it (Actions → release → the run) and approve the deployment only if the run is for the tag you just pushed.
5. The `build` job checks that the run is on the tag it stages, checks the tag against `package.json`, runs the gates (build, test, typecheck) and packs the tarball. The `stage` job checks the tarball is the one `build` packed and **stages** it: it is on npm, but nobody can install it yet.
6. Approve the staged version with 2FA, on npmjs.com → account settings → **Staged Packages** → Approve. **Before approving, check that the staged version's source commit is the tag's commit** (`git rev-parse vX.Y.Z^{commit}`), and that the integrity npm shows for it (`npm stage view <stage-id>`, if it lists one) matches the integrity in the `build` job's run summary (Actions → the run → Summary); this confirms npm received what the `build` job packed, not that the build was clean. Approve only the staged version you tagged. To refuse a staged version, Reject it on the same page.
   - On the command line instead: `npm stage list sweetrust`, `npm stage view <stage-id>`, then `npm stage approve <stage-id>` (or `npm stage reject <stage-id>`). `npm login` leaves a two-hour token in `~/.npmrc`, so run `npm logout` straight after.
7. Check: `npm view sweetrust@X.Y.Z` and the provenance badge on npmjs.com.

**Rules for both packages** (`sweetrust` and `sweetrust-sui`):

- **A manual dispatch must name the tag as its ref.** To re-stage an existing tag, run the workflow with that tag selected under "Use workflow from" (not `main`), and type the same tag in the input. Once the `release` environment is set up (below), it accepts only the `v*` and `sweetrust-sui@*` tag patterns, so a run from `main` or any branch is refused there. The first step of each workflow, which is code, also refuses a ref that differs from the input, so the ref check has two layers: one in the repository's settings and one in the workflows.
- **A tag made before the `release` environment existed is never re-staged.** Its workflow file lacks the environment and runs `npm publish`, which a stage-only publisher should refuse. Make a new tag with the next patch version instead. Never move a tag that has been published.
- **Know what each approval holds.** Once the `release` environment is set up (below), its approval stops a mistaken or unexpected run. It binds only runs of the workflow file as written: anyone with push access can tag a commit whose workflow file drops the environment, and that run skips GitHub's approval. The npm approval is the check that holds even then, because only a staged version can result and only a person with 2FA can release it. Approve only what you tagged, and look hard at every staged version.
- **Reject any waiting release run you did not start.** A run waiting for review is in progress and holds the release queue: only one more run can queue behind it, so a third tag cancels the queued second.
- **Approve within a week.** The packed tarball is kept for 7 days; a run approved later fails at download, and the fix is a new patch version.
- **Prereleases are not supported yet.** A version such as `1.0.0-rc.1` builds and then fails at the stage step.

**One-time setup for the `release` environment (GitHub → Settings → Environments, by a repository admin), before the first tag after this change.** Create `release` with a required reviewer (the releasing maintainer), "Allow administrators to bypass" turned off, and deployments allowed only from the `v*` and `sweetrust-sui@*` tags. Nothing in the workflow files enforces these settings: a job that names an environment the repository does not have runs without protection, so a tag pushed before this setup stages with no GitHub approval, and only the npm approval remains.

**One-time setup for `sweetrust` (npmjs.com, by the package owner).** The kernel's old trusted publisher allowed a direct `npm publish` and was deleted when staging replaced it: npm cannot edit a publisher, only delete and re-create it. Its stage-only replacement is created in the sitting of the first release after this change: package settings → Trusted Publisher → GitHub Actions, organization `sweeai`, repository `sweetrust`, workflow `release.yml`, Environment `release`, and both boxes under *Allowed actions* ("Allow npm publish" and "Allow npm dist-tag") unticked; npm states that `npm stage publish` is always allowed. A new trusted publisher must complete its first publish within two days or it expires, so in that sitting create the publisher, push the tag, approve the run on GitHub and approve the staged version on npm the same day. npm's documentation does not say whether it enforces the Environment field, and does not say whether a staged publish that you approve counts as the first publish; if the publisher expires, create it again.

## Releasing `sweetrust-sui`

The same steps, with the adapter's files and its own tag namespace. `.github/workflows/release-sui.yml` runs on a `sweetrust-sui@*` tag, which never matches `v*`, so a tag can publish only the package it names.

1. On a branch from `main`, make one commit, `release: sweetrust-sui X.Y.Z`: `packages/sui/package.json`, `packages/sui/CHANGELOG.md` (with a link at the bottom) and `packages/sui/README.md` § *Status*, as above. If the release needs a newer kernel, raise the `sweetrust` peer range in the same commit, and release the kernel first.
2. Open a pull request; merge it when CI is green.
3. `git tag -a sweetrust-sui@X.Y.Z <merge-sha> -m "sweetrust-sui X.Y.Z" && git push origin sweetrust-sui@X.Y.Z`
4. The `build` job checks the tag against `packages/sui/package.json`, builds the kernel, runs the adapter's gates (build, test, typecheck) and packs the tarball. The `stage` job then stops at **Waiting for review** on the `release` environment; approve it only if it is for the tag you just pushed. It checks the tarball is the one `build` packed and **stages** the version: it is on npm but nobody can install it yet.
5. A maintainer approves it with 2FA: on npmjs.com → account settings → **Staged Packages** → Approve, or on the command line `npm stage list sweetrust-sui`, `npm stage view <stage-id>`, `npm stage approve <stage-id>` (then `npm logout`). **Before approving, check that the staged version's source commit is the tag's commit** (`git rev-parse sweetrust-sui@X.Y.Z^{commit}`) and that its integrity matches the one in the `build` job's run summary (this confirms npm received what `build` packed, not that the build was clean): anyone with write access can push a tag or dispatch the workflow, so this approval is the check that holds. Approval is the release. To refuse a staged version instead, Reject it there or run `npm stage reject <stage-id>`.
6. Check: `npm view sweetrust-sui@X.Y.Z` and the provenance badge on npmjs.com.

The trusted publisher for `sweetrust-sui` allows `npm stage publish` only ("Allow npm publish" unticked), as `npm help stage` advises. Staging needs npm ≥ 11.15.0.

**Set up once, 2026-11-15.** The name was claimed with a code-less `0.0.1` (as `sweetrust` was before 0.4.0), so npmjs.com could offer the Trusted Publisher form: GitHub Actions, organization `sweeai`, repository `sweetrust`, workflow `release-sui.yml`, no environment, and both boxes under *Allowed actions* ("Allow npm publish" and "Allow npm dist-tag") unticked; the form states that `npm stage publish` is always allowed. A new trusted publisher must complete its first publish within two days or it expires, so the first release is staged and approved in the same sitting the publisher is saved.
