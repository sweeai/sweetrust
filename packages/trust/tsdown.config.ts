import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { defineConfig } from 'tsdown';

// Internal ticket references (`(DAN-904)`) stay in SOURCE, where they are
// provenance. They are stripped from what ships. The source convention that
// makes this safe: a ticket id only ever appears as a TRAILING parenthetical
// that the sentence reads fine without — never as a word in the sentence.
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

// Checks the files ON DISK, after the write. A check that cannot see its
// input must not pass: an empty or missing dist/ reads as "0 found", so the
// positive control comes first.
function assertShippedFilesClean(outDir: string): void {
  const files = readdirSync(outDir);
  const code = files.filter((f) => f.endsWith('.mjs'));
  const types = files.filter((f) => f.endsWith('.d.mts'));
  if (code.length === 0 || types.length === 0) {
    throw new Error(`ship check: ${outDir} has ${code.length} .mjs and ${types.length} .d.mts files; expected both`);
  }
  const maps = files.filter((f) => f.endsWith('.map'));
  if (maps.length > 0) throw new Error(`ship check: sourcemaps would ship: ${maps.join(', ')}`);
  for (const f of [...code, ...types]) {
    const lines = readFileSync(join(outDir, f), 'utf8').split('\n');
    const hit = lines.findIndex((line) => TICKET_ID.test(line));
    if (hit !== -1) {
      throw new Error(
        `ship check: ticket id survived in ${f}:${hit + 1}: ${lines[hit].trim()}\n` +
          '  Move it into a trailing parenthetical in the source, e.g. "(DAN-904)".',
      );
    }
  }
}

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
  // A sourcemap embeds the full source, every internal comment included.
  sourcemap: false,
  plugins: [stripTicketRefs],
  hooks: {
    'build:done': (ctx) => {
      assertShippedFilesClean(ctx.options.outDir);
    },
  },
});
