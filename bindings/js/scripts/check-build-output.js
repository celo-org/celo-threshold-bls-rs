// Runs before `npm pack` and `npm publish`. The files under src/ are wasm-pack
// output and are not checked in, and npm leaves a missing entry of `files` out
// of the tarball without complaint, so without this check a tree that was never
// built packs into a package with no code in it.
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const { files } = require(path.join(root, 'package.json'));
const missing = files.filter((file) => !fs.existsSync(path.join(root, file)));

if (missing.length > 0) {
  console.error(`Cannot pack: missing ${missing.join(', ')}.`);
  console.error('Build the wasm package first; see "Building from source" in README.md.');
  process.exit(1);
}
