const assert = require('node:assert/strict');
const fs = require('node:fs');
const test = require('node:test');

const workflow = fs.readFileSync('.github/workflows/go-ci.yml', 'utf8');
const nested = fs.readFileSync('.github/workflows/linux-cli-module.yml', 'utf8');
function job(name, source = workflow) {
  const marker = `\n  ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing ${name}`);
  const body = source.slice(start + marker.length);
  const end = body.search(/^  [a-zA-Z][a-zA-Z0-9_-]*:\s*$/m);
  return end < 0 ? body : body.slice(0, end);
}

test('required cross-runtime inventory has sixteen exhaustive owners, not a concurrency cap', () => {
  const body = job('cross-runtime');
  assert.match(body, /fail-fast: false/);
  assert.doesNotMatch(body, /max-parallel:|continue-on-error:/);
  assert.match(body, /owner: \[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15\]/);
  assert.match(body, /-ci-isolate-root TestCrossLinuxRuntimeMatrix/);
  assert.match(body, /-ci-owner \$\{\{ matrix.owner \}\}/);
  assert.match(body, /-shards 16 -timeout 20m/);
  assert.match(body, /\^\(TestCrossLinuxRuntimeMatrix\|TestARM64Conformance\|TestARM64RawSQSHLURuntimeSemantics\|TestARMIntegerMemoryRuntimeCross\|TestARMRawSaturationRuntimeCross\)/);
  assert.match(body, /PLAN9ASM_CROSS_EXEC: '1'/);
  assert.match(body, /bash scripts\/install-ci-qemu.sh/);
  assert.match(body, /actions\/upload-artifact@v6/);
  assert.match(body, /if: \$\{\{ !cancelled\(\) \}\}/);
});

test('strict completion runs even after a failed owner and keeps original tool requirements', () => {
  const body = job('cross-runtime-verify');
  assert.match(body, /needs: cross-runtime/);
  assert.match(body, /if: \$\{\{ !cancelled\(\) \}\}/);
  assert.match(body, /-verify-ci-partitions _out\/cross-runtime-partitions/);
  assert.match(body, /-shards 16 -timeout 20m/);
  assert.match(body, /-ci-isolate-root TestCrossLinuxRuntimeMatrix/);
  assert.match(body, /actions\/download-artifact@v8/);
  assert.match(body, /gcc-i686-linux-gnu gcc-arm-linux-gnueabihf/);
  assert.match(body, /gcc-aarch64-linux-gnu/);
  assert.match(body, /bash scripts\/install-ci-qemu.sh/);
  assert.doesNotMatch(body, /continue-on-error:|PLAN9ASM_CROSS_EXEC: '0'/);
});

function requireARM64FallbackOwner(source) {
  const owner = job('cross-runtime', source);
  assert.match(owner, /- name: Execute rich CLI ARM64 fallback oracle\n        if: \$\{\{ !cancelled\(\) && matrix\.owner == 15 \}\}\n        run: bash scripts\/test-arm64-fallback-ci\.sh execute/);
  assert.equal((source.match(/- name: Execute rich CLI ARM64 fallback oracle/g) || []).length, 1);
  const reader = job('cross-runtime-verify', source);
  assert.match(reader, /- name: Verify rich CLI ARM64 fallback execution\n        if: \$\{\{ !cancelled\(\) \}\}\n        run: bash scripts\/test-arm64-fallback-ci\.sh complete/);
}

test('rich CLI ARM64 execution has a unique cross owner and a fresh completion reader', () => {
  requireARM64FallbackOwner(workflow);
});

test('ARM64 execution cannot lose its unique owner, success guard or reader', () => {
  for (const [before, after] of [
    ['Execute rich CLI ARM64 fallback oracle', 'Removed runtime oracle'],
    ['matrix.owner == 15', 'matrix.owner == 14'],
    ['!cancelled() && matrix.owner == 15', 'success()'],
    ['test-arm64-fallback-ci.sh execute', 'test-arm64-fallback-ci.sh complete'],
    ['Verify rich CLI ARM64 fallback execution', 'Removed execution reader'],
  ]) {
    const changed = workflow.replace(before, after);
    assert.notEqual(changed, workflow);
    assert.throws(() => requireARM64FallbackOwner(changed));
  }
  assert.throws(() => requireARM64FallbackOwner(workflow + '\n      - name: Execute rich CLI ARM64 fallback oracle\n'));
});

const moduleExecutionJobs = [
  ...['test', 'race', 'coverage', 'module-completion'].map(name => [workflow, name]),
  ...['root-parts', 'complete'].map(name => [nested, name]),
];
const moduleCompilerInstall = 'bash scripts/install-ci-llvm22-ubuntu.sh ' +
  'gcc-i686-linux-gnu libc6-dev-i386-cross gcc-aarch64-linux-gnu';

// The unchanged portable FMA access oracle executes AArch64 on Linux/amd64
// in ordinary module owners too. Its linker cannot be supplied solely by the
// separate cross-runtime job, nor can missing infrastructure become a skip.
function requireModuleCrossTools(source, name) {
  const body = job(name, source);
  const installs = body.split(/(?=^      - )/m).filter(step =>
    step.includes('run: bash scripts/install-ci-llvm22-ubuntu.sh'));
  assert.equal(installs.length, 1, `${name}: one LLVM/cross-compiler install`);
  assert.match(installs[0], /^        timeout-minutes: 14$/m);
  assert.ok(installs[0].includes(`        run: ${moduleCompilerInstall}\n`),
    `${name}: both 386 and AArch64 module execution dependencies required`);
  assert.doesNotMatch(installs[0], /continue-on-error:|\|\|\s*true/);
  assert.match(body, /^        run: bash scripts\/install-ci-qemu\.sh$/m);
}

// The intended complete installation is an independent positive control; the
// real workflow below must satisfy exactly the same requirement on its own.
for (const [source, name] of moduleExecutionJobs) {
  const moduleToolsFixture = source.replaceAll(
    'bash scripts/install-ci-llvm22-ubuntu.sh gcc-i686-linux-gnu libc6-dev-i386-cross\n',
    moduleCompilerInstall + '\n');
  test(`${name}: real module execution owns its required cross tools`, () => {
    requireModuleCrossTools(source, name);
  });

  test(`${name}: complete cross tools reject missing dependencies or swallowed errors`, () => {
    requireModuleCrossTools(moduleToolsFixture, name);
    const original = job(name, moduleToolsFixture);
    for (const [before, after] of [
      [' gcc-aarch64-linux-gnu', ''],
      [' gcc-i686-linux-gnu', ''],
      [' libc6-dev-i386-cross', ''],
      ['install-ci-llvm22-ubuntu.sh', 'install-unpinned-llvm.sh'],
      [moduleCompilerInstall, moduleCompilerInstall + ' || true'],
      ['install-ci-qemu.sh', 'install-unpinned-qemu.sh'],
    ]) {
      const mutated = original.replace(before, after);
      assert.notEqual(mutated, original, `${name}: mutation changed its own job`);
      // Shell regexes can contain $'; a function keeps replacement bytes literal.
      const changed = moduleToolsFixture.replace(original, () => mutated);
      assert.equal(job(name, changed), mutated, 'mutation must retain its exact job boundary');
      assert.throws(() => requireModuleCrossTools(changed, name), undefined,
        `${name}: reject ${before}`);
    }
  });
}

test('ARM64 main driver retains the complete strict oracle and its four mandatory children', () => {
  const driver = fs.readFileSync('scripts/test-arm64-fallback-ci.sh', 'utf8');
  assert.match(driver, /root=TestFallbackARM64WideFrameCompilesWithLLVM22\n/);
  assert.match(driver, /-dir cmd\/plan9asmll/);
  assert.match(driver, /-ci-selector "\^\$\{root\}\$" -ci-isolate-root "\$root"/);
  assert.match(driver, /-shards 2 -timeout 5m/);
  assert.match(driver, /for owner in 0 1; do/);
  assert.match(driver, /-verify-ci-partitions "\$base\/owners"/);
  assert.match(driver, /node \.github\/scripts\/audit-arm64-fallback\.cjs/);
  const auditor = fs.readFileSync('.github/scripts/audit-arm64-fallback.cjs', 'utf8');
  assert.match(auditor, /\['darwin', 'linux', 'windows', 'native_complete-argument_oracle'\]/);
  assert.match(auditor, /roots: 1, children: 4, passed: 5, skipped: 0, incomplete: 0/);
  const qemu = fs.readFileSync('scripts/install-ci-qemu.sh', 'utf8');
  assert.match(qemu, /^version=10\.2\.3$/m);
  assert.match(qemu, /sha256sum --check --status/);
});
