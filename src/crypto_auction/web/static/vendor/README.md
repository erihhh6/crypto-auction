# Vendored third-party code

Copied verbatim, so the page needs no CDN at runtime and the code it runs is
pinned and reviewable here.

| File | Source | Version | License |
|---|---|---|---|
| `noble-secp256k1.js` | `index.js` from the npm package [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) | 3.2.0 | MIT, see `noble-secp256k1.LICENSE` |

Provenance of `noble-secp256k1.js`:

- npm tarball integrity: `sha512-Z3ZAWOTxJ0EuTuZTi7Y69iK7GgrLHh8sgm45lVDhg/b3Nk1TpAiKhick2KkZisHuupeepSkyIydN/J459SdX1w==`
- SHA-256 of the file: `ba5aadb469e9208f2da1c9878ab6bb93d2c894f84e6c7ebf9dbf9462741b9fb7`

The same version is listed in the repository's `package.json`, so Dependabot
proposes its updates and reports its security advisories. `tests/js/vendor.test.mjs`
checks that this copy is that package's `index.js`, byte for byte, and fails
on a version bump until the copy follows.

To update (or to complete a Dependabot pull request): set the version in
`package.json` and run `npm install`, review the diff between this file and
`node_modules/@noble/secp256k1/index.js`, copy it here, and update this table
and both hashes (the integrity is in `package-lock.json`).
