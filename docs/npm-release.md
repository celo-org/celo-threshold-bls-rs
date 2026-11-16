# Releasing the npm package

`@celo/blind-threshold-bls` is published by `.github/workflows/npm_publish.yml`
and by nothing else. The workflow builds the wasm package from the tagged
commit, runs the jest suite against it, packs the tarball, and publishes that
same tarball once a reviewer approves. npm records provenance for it, so the
package page names the commit and the workflow run it came from.

## Cutting a release

1. Set `version` in `bindings/js/package.json`, and move the changelog entries
   the release ships out of `[Unreleased]`. Merge that to `main`.
2. Tag the merged commit and push the tag:

   ```sh
   git tag js-v<version> <commit>
   git push origin js-v<version>
   ```

3. The `package` job builds and tests. The `publish` job then waits for a
   reviewer of the `npm` environment; the tarball is attached to the run as the
   `npm-tarball` artifact for them to inspect.

The workflow refuses a tag that does not match the version in `package.json`,
and a tagged commit that is not on `main`. A version with a prerelease suffix
(`1.1.0-rc.1`) is published under the `next` dist-tag; anything else becomes
`latest`.

A published version is permanent: npm does not allow the same version to be
published twice, and unpublishing is restricted. A bad release is fixed by
publishing the next version.

## One-time setup

Both must be in place before the first tag is pushed.

- **npm trusted publisher.** A maintainer of the package adds one at
  npmjs.com, under the package's settings: organization `celo-org`, repository
  `celo-threshold-bls-rs`, workflow filename `npm_publish.yml`, environment
  `npm`. The workflow holds no npm token; the registry accepts the job's OIDC
  token because of this entry. Renaming the workflow file or the environment
  breaks publishing until the entry is changed to match.
- **GitHub environment.** A repository admin creates the environment `npm` with
  required reviewers. If the environment does not exist, GitHub creates it on
  first use with no reviewers, and the publish runs unreviewed.

## Publishing by hand

Don't. A tarball published from a laptop carries no provenance, and nobody can
check which source it was built from. `npm pack` and `npm publish` in
`bindings/js` fail when `src/` has not been built, which stops an empty package
but not an unreviewed one.
