import { defineConfig } from 'tsdown';

export default defineConfig({
  // One entry per public subpath. The keys MUST match the `exports` map in
  // package.json — `./mandate` is served by `dist/mandate.mjs`, and nothing
  // checks that correspondence but this comment and the smoke test.
  entry: {
    index: 'src/index.ts',
    mandate: 'src/mandate/index.ts',
    gate: 'src/gate/index.ts',
    verify: 'src/verify/index.ts',
  },
  format: ['esm'],
  dts: true,
  sourcemap: true,
});
