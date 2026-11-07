import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { defineConfig } from 'tsdown';

// Same ship discipline as packages/trust/tsdown.config.ts: internal ticket
// references stay in SOURCE as trailing parentheticals and are stripped from
// what ships, and the shipped files are checked ON DISK after the write.
const TICKET_PARENTHETICAL = /[ \t]?\(DAN-\d+[^()]*\)/g;
const TICKET_ID = /DAN-\d+/;

const stripTicketRefs = {
  name: 'strip-ticket-refs',
  generateBundle(_options: unknown, bundle: Record<string, { type: string; code?: string }>) {
    for (const file of Object.values(bundle)) {
      if (file.type === 'chunk' && file.code) file.code = file.code.replace(TICKET_PARENTHETICAL, '');
    }
  },
};

// A check that cannot see its input must not pass: an empty dist/ reads as
// "0 found", so the positive control comes first.
function assertShippedFilesClean(outDir: string): void {
  const files = readdirSync(outDir);
  const code = files.filter((f) => f.endsWith('.mjs'));
  const types = files.filter((f) => f.endsWith('.d.mts'));
  if (code.length === 0 || types.length === 0) {
    throw new Error(`ship check: ${outDir} has ${code.length} .mjs and ${types.length} .d.mts files; expected both`);
  }
  for (const f of code) {
    const text = readFileSync(join(outDir, f), 'utf8');
    if (/class Transaction\b|function canonicalJSON\b/.test(text)) {
      throw new Error(`ship check: ${f} bundles a peer (@mysten/sui or sweetrust); they must stay external`);
    }
  }
  const maps = files.filter((f) => f.endsWith('.map'));
  if (maps.length > 0) throw new Error(`ship check: sourcemaps would ship: ${maps.join(', ')}`);
  for (const f of [...code, ...types]) {
    const lines = readFileSync(join(outDir, f), 'utf8').split('\n');
    const hit = lines.findIndex((line) => TICKET_ID.test(line));
    if (hit !== -1) {
      throw new Error(
        `ship check: ticket id survived in ${f}:${hit + 1}: ${lines[hit].trim()}\n` +
          '  Move it into a trailing parenthetical in the source, e.g. "(DAN-1259)".',
      );
    }
  }
}

export default defineConfig({
  // One public entry. The key MUST match the `exports` map in package.json.
  entry: { index: 'src/index.ts' },
  format: ['esm'],
  dts: true,
  sourcemap: false,
  // Peers (@mysten/sui, sweetrust) are imported, never bundled: tsdown leaves
  // peerDependencies external by default, and the ship check below fails the
  // build if a copy of either ever lands in dist/.
  plugins: [stripTicketRefs],
  hooks: {
    'build:done': (ctx) => {
      assertShippedFilesClean(ctx.options.outDir);
    },
  },
});
