/**
 * scripts/readme-typecheck.ts — compile the README's `ts` blocks against the
 * SHIPPED declarations, and run the ones that say what they print.
 *
 * Same discipline as packages/trust/scripts/readme-typecheck.ts (read its header
 * for why each rule exists): one program per block, a coverage floor, and an
 * unknown directive fails the gate. The difference is where blocks compile:
 * INSIDE the package directory, so `import "sweetrust-sui"` resolves by package
 * self-reference through `exports` to `dist/`, and `@mysten/sui/*` and
 * `sweetrust/*` resolve from this package's own node_modules, exactly as a
 * consumer's would.
 *
 * DIRECTIVES — an HTML comment immediately before a fence:
 *
 *   <!-- readme-check: skip - <reason> -->      not compiled; the reason is printed
 *   <!-- readme-check: prelude ... -->          prepended; for excerpts needing context
 *   <!-- readme-check: run - expect <output> --> compiled, then run offline; stdout
 *                                                (whitespace-collapsed) must equal <output>
 *   <!-- readme-check: testnet - expect <line> --> compiled always; RUN against Sui testnet
 *                                                only when SWEETRUST_SUI_TESTNET_KEYS is set,
 *                                                and its FIRST stdout line (collapsed) must
 *                                                equal <line>. The rest of stdout (the
 *                                                receipt) is printed. Without keys the run is
 *                                                SKIPPED and says so on every run.
 *
 * Run: node --experimental-strip-types scripts/readme-typecheck.ts
 */
import { execFileSync } from "node:child_process"
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const README = join(PKG, "README.md")
const KEYS = process.env.SWEETRUST_SUI_TESTNET_KEYS

const die = (...lines: Array<string>): never => {
  for (const l of lines) console.error(l)
  process.exit(1)
}

for (const rel of ["./dist/index.d.mts", "./node_modules/sweetrust/dist/verify.d.mts"]) {
  if (!existsSync(join(PKG, rel))) {
    die(`❌ readme-typecheck: ${rel} is missing. Run \`pnpm build\` (from the repo root, so sweetrust builds too).`,
      "   This gate checks the SHIPPED declarations by design. A gate that cannot check is not a pass.")
  }
}

type Block = {
  readonly index: number
  readonly line: number
  readonly body: string
  readonly skip: string | null
  readonly prelude: string
  readonly expect: string | null
  readonly testnet: string | null
}

const md = readFileSync(README, "utf-8")
const blocks: Array<Block> = []
const fence = /```(ts|typescript|tsx)\n([\s\S]*?)```/g
let m: RegExpExecArray | null
let n = 0
while ((m = fence.exec(md)) !== null) {
  n += 1
  const before = md.slice(0, m.index)
  const tail = before.slice(-1000)
  const skip = /<!--\s*readme-check:\s*skip\s*-\s*([^>]*?)-->\s*$/.exec(tail)
  const prelude = /<!--\s*readme-check:\s*prelude\n([\s\S]*?)-->\s*$/.exec(tail)
  const run = /<!--\s*readme-check:\s*run\s*-\s*expect\s+([^>]*?)\s*-->\s*$/.exec(tail)
  const testnet = /<!--\s*readme-check:\s*testnet\s*-\s*expect\s+([^>]*?)\s*-->\s*$/.exec(tail)
  const any = /<!--\s*readme-check:\s*([^\s>]+)[^>]*-->\s*$/.exec(tail)
  if (any !== null && skip === null && prelude === null && run === null && testnet === null) {
    die(`❌ readme-typecheck: unknown directive "readme-check: ${any[1]}" above the block at README.md:${before.split("\n").length}.`,
      "   Known: skip - <reason> · prelude · run - expect <output> · testnet - expect <first line>.")
  }
  blocks.push({
    index: n,
    line: before.split("\n").length,
    body: m[2],
    skip: skip === null ? null : skip[1].trim(),
    prelude: prelude === null ? "" : prelude[1],
    expect: run === null ? null : run[1].replace(/\s+/g, " ").trim(),
    testnet: testnet === null ? null : testnet[1].replace(/\s+/g, " ").trim(),
  })
}

// Floors: this gate gets greener the fewer blocks it looks at, so the counts
// are pinned. Data, not a dial: raise them when you add an example.
const BLOCK_FLOOR = 3
const RUN_FLOOR = 1
const TESTNET_FLOOR = 1

const checked = blocks.filter((b) => b.skip === null)
const runs = checked.filter((b) => b.expect !== null)
const testnets = checked.filter((b) => b.testnet !== null)
console.log(`readme-typecheck: ${blocks.length} \`ts\` blocks · ${checked.length} to compile · ${runs.length} to run offline · ${testnets.length} to run on testnet`)
for (const b of blocks) if (b.skip !== null) console.log(`  ⏭  L${b.line} SKIPPED — ${b.skip}`)
if (checked.length < BLOCK_FLOOR) die(`❌ readme-typecheck: compiled ${checked.length} block(s), floor is ${BLOCK_FLOOR}.`)
if (runs.length < RUN_FLOOR) die(`❌ readme-typecheck: ${runs.length} offline run block(s), floor is ${RUN_FLOOR}.`)
if (testnets.length < TESTNET_FLOOR) die(`❌ readme-typecheck: ${testnets.length} testnet block(s), floor is ${TESTNET_FLOOR}.`)

const work = mkdtempSync(join(PKG, ".readme-run-"))
let failures = 0
try {
  // ── Compile, one program per block ──
  for (const b of checked) {
    if ((b.expect !== null || b.testnet !== null) && b.prelude !== "") die(`❌ readme-typecheck: the run block at README.md:${b.line} has a prelude. A run block must stand alone.`)
    const file = join(work, `block-${b.index}.ts`)
    writeFileSync(file, `// README.md line ${b.line} — generated, do not edit\n${b.prelude}${b.body}`)
    const tsconfig = join(work, `tsconfig.block-${b.index}.json`)
    writeFileSync(tsconfig, JSON.stringify({
      compilerOptions: {
        strict: true, target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext", noEmit: true, skipLibCheck: true,
        types: ["node"], allowImportingTsExtensions: true,
      },
      files: [file],
    }))
    try {
      execFileSync(join(PKG, "node_modules/.bin/tsc"), ["-p", tsconfig], { stdio: "pipe", cwd: PKG })
      console.log(`  ✔  L${b.line} compiled${b.prelude === "" ? "" : " (with prelude)"}`)
    } catch (err: unknown) {
      const e = err as { stdout?: Buffer; stderr?: Buffer }
      const out = `${e.stdout?.toString() ?? ""}${e.stderr?.toString() ?? ""}`
      const configError = out.split("\n").find((l) => /error TS[56]\d{3}:/.test(l))
      if (configError !== undefined) die(`❌ readme-typecheck: the compiler did not run on the block at README.md:${b.line}.`, `   ${configError}`)
      console.log(`  ✘  L${b.line} FAILED`)
      console.error(out.replace(/\S*block-\d+\.ts\((\d+),(\d+)\)/g, (_a, ln, col) => `README.md(${b.line + Number(ln) - 1 - (b.prelude === "" ? 0 : b.prelude.split("\n").length - 1)},${col})`).trim())
      failures += 1
    }
  }
  if (failures > 0) die(`❌ readme-typecheck FAILED — ${failures} README block(s) do not compile against the shipped types.`)
  console.log("✅ readme-typecheck: README compiles against the shipped declarations.")

  // ── Run ──
  const exec = (b: Block, timeout: number): string | null => {
    try {
      return execFileSync(process.execPath, ["--experimental-strip-types", "--no-warnings", join(work, `block-${b.index}.ts`)], {
        stdio: ["ignore", "pipe", "pipe"], cwd: PKG, timeout,
      }).toString()
    } catch (err: unknown) {
      const e = err as { stdout?: Buffer; stderr?: Buffer }
      console.log(`  ✘  L${b.line} RUN FAILED — the block threw`)
      console.error(`${e.stdout?.toString() ?? ""}${e.stderr?.toString() ?? ""}`.trim())
      return null
    }
  }
  for (const b of runs) {
    const out = exec(b, 60_000)
    const got = out?.replace(/\s+/g, " ").trim()
    if (got === undefined) { failures += 1; continue }
    if (got !== b.expect) {
      console.log(`  ✘  L${b.line} RUN OUTPUT MISMATCH\n     expected: ${b.expect}\n     got:      ${got}`)
      failures += 1
      continue
    }
    console.log(`  ✔  L${b.line} ran offline against dist/, printed: ${got}`)
  }
  for (const b of testnets) {
    if (!KEYS) {
      console.log(`  ⚠️  L${b.line} TESTNET RUN SKIPPED — SWEETRUST_SUI_TESTNET_KEYS is not set. The block compiled; its behavior on chain was NOT checked.`)
      continue
    }
    const out = exec(b, 300_000)
    if (out === null) { failures += 1; continue }
    const [first, ...rest] = out.split("\n")
    const got = first.replace(/\s+/g, " ").trim()
    if (got !== b.testnet) {
      console.log(`  ✘  L${b.line} TESTNET OUTPUT MISMATCH\n     expected: ${b.testnet}\n     got:      ${got}`)
      failures += 1
    } else {
      console.log(`  ✔  L${b.line} ran on Sui testnet against dist/, printed: ${got}`)
    }
    console.log(rest.join("\n").trimEnd().replace(/^/gm, "     "))
  }
} finally {
  rmSync(work, { recursive: true, force: true })
}
if (failures > 0) die(`❌ readme-typecheck FAILED — ${failures} README block(s) do not do what they say.`)
console.log("✅ readme-typecheck: every runnable README block printed what it claims.")
