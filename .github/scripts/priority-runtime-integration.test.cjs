'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {jobBody, jobNeeds} = require('./workflow-needs.cjs');

const directory = path.join(__dirname, '../workflows');
const goCI = fs.readFileSync(path.join(directory, 'go-ci.yml'), 'utf8');
const runtimeFile = path.join(directory, 'runtime-integration.yml');
const runtime = fs.existsSync(runtimeFile) ? fs.readFileSync(runtimeFile, 'utf8') : '';
const benchmarkScript = fs.readFileSync(path.join(__dirname, '../../scripts/benchmark-compile.sh'), 'utf8');
const instructionJobs = ['ci_policy', 'fmt', 'build', 'stdlib-corpus', 'cross-runtime',
  'cross-runtime-verify', 'test', 'nested-cli', 'windows-module', 'arm-scan',
  'race', 'coverage', 'nested-cli-coverage', 'module-completion'];
const linuxTargets = ['linux/386', 'linux/amd64', 'linux/arm', 'linux/arm64',
  'darwin/amd64', 'darwin/arm64', 'windows/386', 'windows/amd64', 'windows/arm64', 'js/wasm'];
const corpusTargets = [linuxTargets,
  ...Array.from({length: 7}, () => [...linuxTargets, 'wasip1/wasm']),
  ['darwin/amd64', 'darwin/arm64'], ['windows/386', 'windows/amd64', 'windows/arm64']];

function jobNames(source) {
  const sections = source.split('\njobs:\n');
  assert.equal(sections.length, 2, 'one explicit jobs section');
  return [...sections[1].matchAll(/^  ([a-zA-Z_][a-zA-Z0-9_-]*):\s*$/gm)].map(match => match[1]);
}

function requireJobSet(source, expected) {
  assert.deepEqual(jobNames(source).sort(), expected.slice().sort(), 'complete, unique job ownership');
}

function requireExactSDK(body) {
  const setup = body.split(/(?=^      - )/m).filter(step =>
    /^        uses: \.\/\.github\/actions\/setup-go$/m.test(step));
  assert.equal(setup.length, 1, 'one observed SDK setup');
  assert.match(setup[0], /^          go-version: '1\.27\.2'$/m);
  assert.doesNotMatch(body, /go-version-file:|check-latest:|uses: actions\/setup-go@/);
}

function requireRuntimeIntegration(source) {
  assert.match(source, /^name: SDK\/runtime integration$/m);
  const triggers = source.match(/^on:\n([\s\S]*?)(?=^\S)/m);
  assert.ok(triggers, 'explicit standalone workflow triggers');
  assert.deepEqual([...triggers[1].matchAll(/^  ([a-z_]+):[^\n]*$/gm)].map(match => match[1]),
    ['workflow_dispatch', 'schedule']);
  assert.match(triggers[1], /^    - cron: '17 3 \* \* 1'$/m, 'one weekly schedule');
  assert.equal([...triggers[1].matchAll(/cron:/g)].length, 1);
  assert.match(source, /^  cancel-in-progress: false$/m);
  assert.match(source, /^permissions:\n  contents: read$/m);
  requireJobSet(source, ['ci_policy', 'benchmark', 'stdlib-corpus']);
  assert.doesNotMatch(source, /continue-on-error:|\|\|\s*true|\bexit 0\b/);
  assert.doesNotMatch(source, /PLAN9ASM_BENCHMARK_(?:TARGETS|REPORT_DIR):/);

  const policy = jobBody(source, 'ci_policy');
  assert.doesNotMatch(policy, /^    (?:needs|if):/m);
  assert.match(policy, /^    timeout-minutes: 20$/m);
  assert.match(policy, /^        run: bash scripts\/install-ci-llvm22-ubuntu\.sh$/m);
  assert.match(policy, /^        run: node --test \.github\/scripts\/priority-\*\.test\.cjs$/m);
  assert.match(policy, /^        run: go test \. -run '\^TestCI' -count=1$/m);
  requireExactSDK(policy);

  const job = jobBody(source, 'benchmark');
  assert.deepEqual(jobNeeds(source, 'benchmark'), ['ci_policy']);
  assert.match(job, /^    name: complete standard-library SDK\/runtime compile \(Go 1\.27, LLVM 22\)$/m);
  assert.match(job, /^    timeout-minutes: 35$/m);
  assert.doesNotMatch(job, /^    if:/m);
  requireExactSDK(job);
  const steps = job.split(/(?=^      - )/m).slice(1);
  assert.equal(steps.length, 5, 'retain every original execution and report step');
  assert.match(steps[0], /^        uses: actions\/checkout@v7$/m);
  assert.match(steps[1], /^        run: bash scripts\/install-ci-llvm22-ubuntu\.sh$/m);
  assert.match(steps[1], /^        timeout-minutes: 14$/m);
  for (const step of steps.slice(0, 4)) assert.doesNotMatch(step, /^        if:/m);
  assert.match(steps[3], /^        run: scripts\/benchmark-compile\.sh$/m);
  const environment = [...steps[3].matchAll(/^          ([A-Z0-9_]+): (.+)$/gm)];
  assert.deepEqual(environment.map(match => [match[1], match[2]]), [
    ['PLAN9ASM_BENCHMARK_MAX_TARGET_SECONDS', "'300'"],
    ['PLAN9ASM_BENCHMARK_MAX_TOTAL_SECONDS', "'900'"],
  ]);
  assert.match(steps[4], /^        if: always\(\)$/m);
  assert.match(steps[4], /^        uses: actions\/upload-artifact@v6$/m);
  assert.match(steps[4], /^          name: compile-benchmark$/m);
  assert.match(steps[4], /^          path: _out\/compile-benchmark$/m);
  assert.match(steps[4], /^          if-no-files-found: error$/m);

  const corpus = jobBody(source, 'stdlib-corpus');
  assert.deepEqual(jobNeeds(source, 'stdlib-corpus'), ['ci_policy']);
  assert.match(corpus, /^    name: complete stdlib source\/object corpus \(/m);
  assert.doesNotMatch(corpus, /^    if:|--instructions-only/m);
  assert.match(corpus, /^          scripts\/check-stdlib-corpus\.sh$/m);
  requireCorpusTargets(corpus);
  // The complete matrix, tools and prebuild transport are still the original
  // corpus job. Only its instruction-only call and redundant official-table
  // step differ from the required PR instruction owner.
  assert.equal(corpusBody(corpus), corpusBody(jobBody(goCI, 'stdlib-corpus')),
    'full SDK/OS/architecture-profile matrix and tool requirements must match');
}

function corpusBody(body) {
  return body.replace(/^    name: [^\n]+\n/m, '')
    .replace('scripts/check-stdlib-corpus.sh --instructions-only', 'scripts/check-stdlib-corpus.sh')
    .split('\n      - name: Official Go assembler coverage regression\n')[0].trimEnd();
}

function requireCorpusTargets(body) {
  const actual = [...body.matchAll(/targets: '([^']+)'/g)].map(match => match[1].split(','));
  assert.deepEqual(actual, corpusTargets,
    'every SDK/host lane must retain its complete, independently known OS/architecture inventory');
}

function requireInstructionOwners(source) {
  requireJobSet(source, instructionJobs);
  assert.doesNotMatch(source, /runtime-integration\.yml|scripts\/benchmark-compile\.sh/);
  for (const name of ['fmt', 'build', 'stdlib-corpus', 'cross-runtime', 'test', 'nested-cli',
    'windows-module', 'arm-scan', 'race', 'coverage', 'nested-cli-coverage']) {
    assert.deepEqual(jobNeeds(source, name), ['ci_policy'], name);
    assert.doesNotMatch(jobBody(source, name), /^    if:|continue-on-error:/m, name);
  }
  assert.deepEqual(jobNeeds(source, 'cross-runtime-verify'), ['cross-runtime']);
  assert.deepEqual(jobNeeds(source, 'module-completion'),
    ['test', 'nested-cli', 'race', 'coverage', 'nested-cli-coverage']);
  assert.match(jobBody(source, 'build'), /run: scripts\/check-arm64-plan9-corpus\.sh/);
  const corpus = jobBody(source, 'stdlib-corpus');
  assert.match(corpus, /^    name: stdlib instruction corpus \(/m);
  assert.match(corpus, /^          scripts\/check-stdlib-corpus\.sh --instructions-only$/m);
  assert.match(corpus, /scripts\/check-go-asm-coverage\.sh/);
  requireCorpusTargets(corpus);
  assert.match(jobBody(source, 'cross-runtime'), /scripts\/install-ci-qemu\.sh/);
  assert.match(jobBody(source, 'windows-module'), /uses: \.\/\.github\/workflows\/windows-module\.yml/);
  assert.match(jobBody(source, 'coverage'), /bash scripts\/test-module-ci\.sh coverage execute/);
  assert.match(jobBody(source, 'module-completion'), /files: \.\/coverage-root\.out/);
}

function withoutJob(source, name) {
  return source.replace('\n  ' + name + ':\n' + jobBody(source, name), '\n');
}

// The positive mutation fixture is the intended move of the real existing
// job, not a claimed execution result. Actual workflow tests below never use
// this fallback to hide a missing integration workflow.
let instructionFixture = /\n  benchmark:\n/.test(goCI) ? withoutJob(goCI, 'benchmark') : goCI;
instructionFixture = instructionFixture.replace('name: stdlib-corpus (', 'name: stdlib instruction corpus (')
  .replace('          scripts/check-stdlib-corpus.sh\n', '          scripts/check-stdlib-corpus.sh --instructions-only\n');
let runtimeFixture = runtime;
if (!runtimeFixture) {
  const policy = jobBody(goCI, 'ci_policy').replace("go-version: '1.27.1'", "go-version: '1.27.2'");
  const benchmark = jobBody(goCI, 'benchmark').replace('name: compile benchmark (Go 1.27, LLVM 22)',
    'name: complete standard-library SDK/runtime compile (Go 1.27, LLVM 22)');
  const corpus = jobBody(goCI, 'stdlib-corpus')
    .replace('name: stdlib-corpus (', 'name: complete stdlib source/object corpus (')
    .split('\n      - name: Official Go assembler coverage regression\n')[0];
  runtimeFixture = "name: SDK/runtime integration\n\non:\n  workflow_dispatch:\n  schedule:\n" +
    "    - cron: '17 3 * * 1'\n\nconcurrency:\n" +
    "  group: ${{ github.workflow }}-${{ github.ref }}\n  cancel-in-progress: false\n\n" +
    'permissions:\n  contents: read\n\njobs:\n  ci_policy:\n' + policy + '\n  benchmark:\n' + benchmark +
    '\n  stdlib-corpus:\n' + corpus;
}

test('complete SDK/runtime integration has independent manual and weekly strict ownership', () => {
  requireRuntimeIntegration(runtime);
});

test('PR Go CI retains every instruction owner without a successful runtime placeholder', () => {
  requireInstructionOwners(goCI);
});

test('the unchanged strict benchmark still requires full five-target whole-source compilation', () => {
  assert.ok(benchmarkScript.includes('targets_csv=${PLAN9ASM_BENCHMARK_TARGETS:-linux/386,linux/amd64,linux/arm,linux/arm64,js/wasm}'));
  for (const flag of ['-patterns=std', '-compile', '-strict-load', '-keep-going=true']) {
    assert.ok(benchmarkScript.includes('    ' + flag + ' \\'), flag);
  }
  assert.match(benchmarkScript, /\.failed == 0 and \.not_applicable == 0 and \.success == \.total_asm/);
  assert.match(benchmarkScript, /if \(\( budget_failed != 0 \|\| compile_failed != 0 \)\); then\n  exit 1/);
  assert.match(benchmarkScript, /benchmark reports already exist; select a fresh PLAN9ASM_BENCHMARK_REPORT_DIR/);
});

test('runtime policy rejects trigger, compiler, budget, source, report and failure masking drift', async t => {
  requireRuntimeIntegration(runtimeFixture);
  const changes = [
    ['PR trigger', '  workflow_dispatch:\n', '  workflow_dispatch:\n  pull_request:\n'],
    ['inline PR trigger', '  workflow_dispatch:\n', '  workflow_dispatch:\n  pull_request: {}\n'],
    ['push trigger', '  workflow_dispatch:\n', '  workflow_dispatch:\n  push:\n'],
    ['inline push trigger', '  workflow_dispatch:\n', '  workflow_dispatch:\n  push: {}\n'],
    ['call trigger', '  workflow_dispatch:\n', '  workflow_dispatch:\n  workflow_call:\n'],
    ['duplicate manual trigger', '  workflow_dispatch:\n', '  workflow_dispatch:\n  workflow_dispatch: {}\n'],
    ['duplicate schedule trigger', '  schedule:\n', '  schedule:\n  schedule:\n'],
    ['missing manual', '  workflow_dispatch:\n', ''],
    ['daily schedule', "cron: '17 3 * * 1'", "cron: '17 3 * * *'"],
    ['cancel prior evidence', 'cancel-in-progress: false', 'cancel-in-progress: true'],
    ['missing policy command', "run: go test . -run '^TestCI' -count=1", 'run: echo policy'],
    ['foreign SDK', "go-version: '1.27.2'", "go-version: '1.27.3'"],
    ['floating SDK', "go-version: '1.27.2'", "go-version: '1.27.x'"],
    ['wrong LLVM', 'run: bash scripts/install-ci-llvm22-ubuntu.sh', 'run: echo LLVM23'],
    ['job budget', 'timeout-minutes: 35', 'timeout-minutes: 45'],
    ['target budget', "PLAN9ASM_BENCHMARK_MAX_TARGET_SECONDS: '300'", "PLAN9ASM_BENCHMARK_MAX_TARGET_SECONDS: '600'"],
    ['total budget', "PLAN9ASM_BENCHMARK_MAX_TOTAL_SECONDS: '900'", "PLAN9ASM_BENCHMARK_MAX_TOTAL_SECONDS: '1800'"],
    ['partial target override', "PLAN9ASM_BENCHMARK_MAX_TOTAL_SECONDS: '900'", "PLAN9ASM_BENCHMARK_MAX_TOTAL_SECONDS: '900'\n          PLAN9ASM_BENCHMARK_TARGETS: linux/amd64"],
    ['successful placeholder', 'run: scripts/benchmark-compile.sh', 'run: echo success'],
    ['arguments substitute sources', 'run: scripts/benchmark-compile.sh', 'run: scripts/benchmark-compile.sh -patterns=math'],
    ['hidden command failure', 'run: scripts/benchmark-compile.sh', 'run: scripts/benchmark-compile.sh || true'],
    ['hidden job failure', '    timeout-minutes: 35', '    timeout-minutes: 35\n    continue-on-error: true'],
    ['skipped job', '    timeout-minutes: 35', '    timeout-minutes: 35\n    if: false'],
    ['skipped compile', '      - name: Translate and compile standard-library assembly', '      - name: Translate and compile standard-library assembly\n        if: false'],
    ['lost failure report', 'if: always()', 'if: success()'],
    ['missing report', 'if-no-files-found: error', 'if-no-files-found: ignore'],
    ['wrong report', 'path: _out/compile-benchmark', 'path: _out/partial-benchmark'],
    ['runtime corpus reduced to scanning', '          scripts/check-stdlib-corpus.sh\n', '          scripts/check-stdlib-corpus.sh --instructions-only\n'],
    ['missing corpus target', 'linux/arm64,', ''],
    ['missing corpus prebuild', 'go build -C cmd/plan9asm -o "$tool" .', 'echo no-tool'],
  ];
  for (const [name, before, after] of changes) {
    await t.test(name, () => {
      assert.ok(runtimeFixture.includes(before), 'mutation must apply');
      assert.throws(() => requireRuntimeIntegration(runtimeFixture.replaceAll(before, after)));
    });
  }
  await t.test('missing benchmark policy needs', () => {
    assert.throws(() => requireRuntimeIntegration(runtimeFixture.replace('    needs: ci_policy\n', '')));
  });
  await t.test('duplicate benchmark owner', () => {
    assert.throws(() => requireRuntimeIntegration(runtimeFixture + '\n  benchmark:\n    run: true\n'));
  });
  await t.test('missing full source/object corpus owner', () => {
    assert.throws(() => requireRuntimeIntegration(withoutJob(runtimeFixture, 'stdlib-corpus')));
  });
  for (const line of jobBody(runtimeFixture, 'stdlib-corpus').split('\n').filter(line =>
    /^          - \{os: /.test(line))) {
    await t.test('missing full corpus lane ' + line.trim(), () => {
      assert.throws(() => requireRuntimeIntegration(runtimeFixture.replace(line + '\n', '')));
    });
  }
});

test('responsibility split cannot delete or replace a required instruction owner', async t => {
  requireInstructionOwners(instructionFixture);
  for (const name of instructionJobs) {
    await t.test('missing ' + name, () => {
      assert.throws(() => requireInstructionOwners(withoutJob(instructionFixture, name)));
    });
  }
  for (const [before, after] of [
    ['scripts/check-go-asm-coverage.sh', 'echo official-coverage'],
    ['scripts/check-stdlib-corpus.sh', 'echo corpus'],
    ['scripts/check-stdlib-corpus.sh --instructions-only', 'scripts/check-stdlib-corpus.sh'],
    ['scripts/check-arm64-plan9-corpus.sh', 'echo arm64-corpus'],
    ['linux/arm64,', ''],
    ['scripts/install-ci-qemu.sh', 'echo native'],
    ['files: ./coverage-root.out', 'files: ./partial-coverage.out'],
    ['    needs: [test, nested-cli, race, coverage, nested-cli-coverage]',
      '    needs: [test, nested-cli, race, nested-cli-coverage]'],
    ['    needs: [test, nested-cli, race, coverage, nested-cli-coverage]',
      '    needs: [test, nested-cli, race, coverage]'],
    ['uses: ./.github/workflows/windows-module.yml', 'uses: ./.github/workflows/runtime-integration.yml'],
  ]) {
    await t.test('replace ' + before, () => {
      assert.ok(instructionFixture.includes(before), 'mutation must apply');
      assert.throws(() => requireInstructionOwners(instructionFixture.replaceAll(before, after)));
    });
  }
  await t.test('successful old benchmark identity', () => {
    assert.throws(() => requireInstructionOwners(instructionFixture + '\n  benchmark:\n    run: echo success\n'));
  });
});

test('both corpus copies independently reject every missing or duplicate OS/architecture target', async t => {
  requireCorpusTargets(jobBody(goCI, 'stdlib-corpus'));
  requireRuntimeIntegration(runtimeFixture);
  requireInstructionOwners(instructionFixture);
  function replaceTargets(source, lane, targets) {
    const body = jobBody(source, 'stdlib-corpus');
    const field = [...body.matchAll(/targets: '([^']+)'/g)][lane];
    const changed = body.slice(0, field.index) + "targets: '" + targets.join(',') + "'" +
      body.slice(field.index + field[0].length);
    assert.notEqual(changed, body, 'target mutation must apply');
    return source.replace(body, changed);
  }
  for (const [lane, targets] of corpusTargets.entries()) {
    for (const [index, target] of targets.entries()) {
      for (const operation of ['missing', 'duplicate']) {
        await t.test('lane ' + lane + '/' + target + '/' + operation, () => {
          const changed = targets.slice();
          if (operation === 'missing') changed.splice(index, 1);
          else changed.splice(index, 0, target);
          // Change both copies together: cross-workflow equality alone must
          // never make a jointly reduced or duplicated matrix acceptable.
          assert.throws(() => requireInstructionOwners(replaceTargets(instructionFixture, lane, changed)));
          assert.throws(() => requireRuntimeIntegration(replaceTargets(runtimeFixture, lane, changed)));
        });
      }
    }
  }
});
