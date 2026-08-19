# Release procedure

This is the exact, verified procedure for publishing a ProcSeal release to
npm. It exists so a release is a checklist, not something reconstructed
from memory under time pressure.

Publishing is **not automatic on merge**. `.github/workflows/release.yml`
only runs when someone pushes an explicit stable version tag (`vX.Y.Z`) —
never on a normal push to `main`, never on a pull request. Adding or
merging that workflow file does not publish anything by itself.

## One-time prerequisites (before the first publish)

These must be completed once, by a maintainer with npm and GitHub admin
access, before the first `npm publish` can succeed. None of this is done
by this repository's CI — it is manual, external configuration.

1. **Confirm the package name is still available**, immediately before
   bootstrapping: `npm view procseal` should return `404 Not Found`. If
   it now exists and isn't this project, stop and pick a different name.
2. **Bootstrap the package name once.** npm cannot attach a trusted
   publisher until the package already exists. From a throwaway empty
   directory — never from this repository checkout — create and publish a
   package.json-only `procseal@0.0.0` placeholder under a non-default
   dist-tag:
   ```bash
   tmp_dir="$(mktemp -d)"
   cd "$tmp_dir"
   npm init -y
   npm pkg set name=procseal version=0.0.0 \
     description="Bootstrap placeholder for ProcSeal trusted publishing" \
     license=MIT
   npm publish --access public --tag bootstrap
   ```
   This one-time command requires an authenticated npm maintainer account
   and its interactive 2FA/OTP. Inspect the generated tarball before
   confirming. Do not create or store an npm token in this repository or
   in GitHub Actions.
3. **Create npm trusted publishing configuration for `procseal`.** On
   [npmjs.com](https://www.npmjs.com), open the package's Settings →
   Trusted Publisher, choose GitHub Actions, and configure:
   - Organization or user: `studivox`
   - Repository: `procseal`
   - Workflow filename: `release.yml` (filename only, not the
     `.github/workflows/` path)
   - Environment: `npm-publish`
   - Allowed action: `npm publish`

   This lets the release workflow authenticate through a short-lived
   GitHub OIDC token. **No `NPM_TOKEN` is added to this repository.**

4. **(Recommended) Create a GitHub Environment named `npm-publish`** under
   the repository's Settings → Environments, with required reviewers. The
   release workflow already references `environment: npm-publish`; an
   environment with no protection rules behaves exactly like not
   specifying one.
5. **Verify the configuration before tagging.** Confirm the package page
   shows `0.0.0` only under the `bootstrap` dist-tag, the trusted
   publisher fields match exactly, and `0.1.0` remains unpublished.
   After the real `v0.1.0` workflow succeeds, remove the temporary tag
   with `npm dist-tag rm procseal bootstrap`. The immutable `0.0.0`
   version remains in history but is never selected by a normal install.

## Cutting a release

1. On `main`, confirm the working tree is clean and CI is green.
2. Update `package.json`'s `"version"` field to the release version
   (semantic version, no `v` prefix — e.g. `0.1.0`).
3. Finalize `CHANGELOG.md`: move the relevant `[Unreleased]`/pending
   content under a dated `## [X.Y.Z] - YYYY-MM-DD` heading.
4. Commit: `git commit -m "chore(release): vX.Y.Z"`.
5. Push the commit and confirm CI is green on `main` at that commit.
6. Tag and push the tag:
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
   Pushing this tag is what triggers `.github/workflows/release.yml`. It
   re-runs the full validation suite (format, lint, typecheck, unit,
   integration, the isolated real-PM2 E2E test, build, pack inspection),
   verifies the tag matches `package.json`'s version, and only then runs
   `npm publish --provenance --access public`.
7. Watch the workflow run to completion in the Actions tab. If it fails
   at any step before the publish step, nothing was published — fix the
   issue and push a new tag (see "If a tag fails or needs to change"
   below; never force-push or reuse a tag).
8. Once the workflow succeeds, create a GitHub Release from the pushed
   tag, using the corresponding `CHANGELOG.md` section as the release
   notes body.

## Post-publication smoke tests

Run these against the **real, published** package, not a local build —
they're what actually proves the publish worked:

```bash
npm view procseal version                 # matches the tag you just pushed
npm view procseal dist.tarball             # sanity-check the tarball URL
npm view procseal --json | grep provenance # confirms provenance metadata is attached
```

```bash
mkdir /tmp/procseal-smoke-test && cd /tmp/procseal-smoke-test
npm init -y
npm install procseal
./node_modules/.bin/procseal --version     # prints the released version
./node_modules/.bin/procseal --help
./node_modules/.bin/procseal audit --help
```

Also check the [npm package page](https://www.npmjs.com/package/procseal)
shows the green "Provenance" badge, and that the README rendered there
matches what's in the repository (npm renders `README.md` from the
published tarball).

## Rollback and deprecation

npm does not allow re-publishing a version number, and unpublishing is
restricted (generally only within 72 hours, and npm may refuse it if the
package already has dependents). Prefer forward fixes over unpublishing:

- **A bad release with no known security impact:** publish a new patch
  version with the fix, and run `npm deprecate procseal@X.Y.Z "<reason>"`
  pointing at the broken version so `npm install` warns anyone still
  pinned to it.
- **A release with a security impact:** follow [SECURITY.md](../SECURITY.md)
  first — do not discuss details in a public issue or commit message
  before a fix is available. Publish the fixed version, then deprecate
  the affected version(s) with a reason that references the advisory
  once it's public.
- **Truly needs to come off the registry** (e.g. accidentally published
  secrets, malicious tampering): use `npm unpublish` only within npm's
  allowed window, and only as a last resort — it breaks anyone who
  already installed that version and cannot easily be undone.

## If a tag fails or needs to change

Tags are not force-pushed or reused in this project (matching the
repository's general no-force-push policy). If a pushed release tag
turns out to be wrong before the workflow completes successfully:

1. Let the failed run finish or cancel it from the Actions tab.
2. Delete the tag both locally and on the remote:
   `git tag -d vX.Y.Z && git push origin :refs/tags/vX.Y.Z`.
3. Fix the underlying issue, bump to a new version number if the
   `package.json` version was already exposed anywhere externally, and
   start again from "Cutting a release" above with a fresh tag.

Never re-push the same tag name pointing at a different commit once a
publish has actually succeeded for it — that's indistinguishable from a
supply-chain attack to anyone who already fetched that tag.
