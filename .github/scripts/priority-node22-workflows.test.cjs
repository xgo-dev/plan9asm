'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const {test} = require('node:test');
const {jobBody} = require('./workflow-needs.cjs');
const {requireNode22Setup} = require('./node22-setup.cjs');

const roles = {
  'go-ci.yml': ['ci_policy', 'cross-runtime', 'cross-runtime-verify', 'test', 'nested-cli',
    'nested-cli-coverage', 'race', 'coverage', 'module-completion'],
  'windows-module.yml': ['root-parts', 'other-owners', 'complete'],
  'runtime-integration.yml': ['ci_policy'],
};

// Both complete layouts retain the same two CLI installation obligations.
// Once the reusable producer exists, verify its real roles and exact callers;
// a missing callee cannot make the old inline obligations disappear.
const cliWorkflow = '.github/workflows/linux-cli-module.yml';
const usesReusableCLI = fs.existsSync(cliWorkflow);
if (usesReusableCLI) {
  roles['go-ci.yml'] = ['ci_policy', 'cross-runtime', 'cross-runtime-verify', 'test',
    'race', 'coverage', 'module-completion'];
  roles['linux-cli-module.yml'] = ['root-parts', 'complete'];
}

function requireCLICaller(body, coverage) {
  assert.equal((body.match(/^    uses: \.\/\.github\/workflows\/linux-cli-module\.yml$/gm) || []).length, 1);
  assert.match(body, /^    needs: ci_policy$/m);
  assert.match(body, /^      fail-fast: false$/m);
  assert.match(body, /^        module: \[plan9asm, plan9asmll\]$/m);
  assert.match(body, /^      module: \$\{\{ matrix\.module \}\}$/m);
  if (coverage) {
    assert.match(body, /^      go-version: '1\.27\.2'$/m);
    assert.doesNotMatch(body, /^        go-version:/m,
      'coverage has one exact current SDK, not an additional matrix');
  } else {
    assert.ok(body.includes("        go-version: ['1.24.x', '1.25.x', '1.26.x', '1.27.2']\n"));
    assert.match(body, /^      go-version: \$\{\{ matrix\.go-version \}\}$/m);
  }
  assert.ok(body.includes('      flavor: ' + (coverage ? 'coverage' : 'test') + '\n'));
  assert.doesNotMatch(body, /^    (?:if|runs-on|steps|continue-on-error):|max-parallel:/m);
}

if (usesReusableCLI) {
  test('both complete CLI callers preserve their exact reusable runtime obligations', () => {
    const workflow = fs.readFileSync('.github/workflows/go-ci.yml', 'utf8');
    for (const [name, coverage] of [['nested-cli', false], ['nested-cli-coverage', true]]) {
      const body = jobBody(workflow, name);
      requireCLICaller(body, coverage);
      for (const [before, after] of [
        ['uses: ./.github/workflows/linux-cli-module.yml', 'uses: ./.github/workflows/foreign.yml'],
        ['module: [plan9asm, plan9asmll]', 'module: [plan9asm]'],
        ["'1.27.2'", "'1.27.x'"],
        ['flavor: ' + (coverage ? 'coverage' : 'test'), 'flavor: race'],
        ['fail-fast: false', 'fail-fast: true'],
      ]) {
        const changed = body.replace(before, after);
        assert.notEqual(changed, body);
        assert.throws(() => requireCLICaller(changed, coverage));
      }
    }
  });
}

function nodeStep(body) {
  const steps = body.split(/(?=^      - )/m).slice(1).filter(step =>
    step.includes('uses: ./.github/actions/setup-node22'));
  assert.equal(steps.length, 1, 'each required role has exactly one verified Node setup');
  requireNode22Setup(steps[0]);
  assert.doesNotMatch(body, /uses: actions\/setup-node@|node-version:/,
    'another runtime cannot replace or follow the verified exact installer');
  return steps[0];
}

// Derive runtime users separately from the closed role census. A new cross or
// complete-module consumer must not borrow ambient Node just because its name
// was omitted from the list above.
function requireRuntimeNodeDependencies(source) {
  const start = source.indexOf('\njobs:\n');
  assert.ok(start >= 0, 'a formal reusable workflow must retain its job graph');
  const jobs = source.slice(start);
  const observed = [];
  for (const [, name] of jobs.matchAll(/^  ([a-zA-Z0-9_-]+):$/gm)) {
    const body = jobBody(source, name);
    const runtime = /PLAN9ASM_CROSS_EXEC\s*[:=]\s*['"]?1(?:['"]|\s|$)/.test(body) ||
      /scripts\/test-(?:arm64-fallback|(?:linux-cli-|windows-)?module)-ci\.sh/.test(body) ||
      /^ +(?:run: )?node\s/m.test(body) ||
      /^ +run: go test\s/m.test(body);
    if (runtime) {
      nodeStep(body);
      observed.push(name);
    }
  }
  return observed.sort();
}

function requireFormalRuntimeDependencies(readWorkflow) {
  const pending = ['go-ci.yml'];
  const observed = new Map();
  while (pending.length) {
    const name = pending.pop();
    if (observed.has(name)) continue;
    const source = readWorkflow(name);
    observed.set(name, requireRuntimeNodeDependencies(source));
    for (const [, callee] of source.matchAll(
      /^    uses: \.\/\.github\/workflows\/([a-zA-Z0-9_.-]+\.yml)$/gm)) {
      pending.push(callee);
    }
  }
  return observed;
}

test('actual cross-runtime and module consumers independently require verified Node', () => {
  const workflow = fs.readFileSync('.github/workflows/go-ci.yml', 'utf8');
  const readWorkflow = name => fs.readFileSync('.github/workflows/' + name, 'utf8');
  const observed = requireFormalRuntimeDependencies(readWorkflow);
  assert.deepEqual(observed.get('go-ci.yml'),
    ['ci_policy', 'coverage', 'cross-runtime', 'cross-runtime-verify',
      'module-completion', 'race', 'test']);
  const added = workflow + '\n  new-cross-consumer:\n    env:\n' +
    "      PLAN9ASM_CROSS_EXEC: '1'\n    steps:\n      - run: go run ./cmd/plan9asmtest\n";
  assert.throws(() => requireRuntimeNodeDependencies(added),
    'a newly added consumer cannot disappear from Node coverage');
  assert.deepEqual(observed.get('windows-module.yml'), ['complete', 'other-owners', 'root-parts']);
  assert.deepEqual(observed.get('linux-cli-module.yml'), ['complete', 'root-parts']);

  const consumer = "name: New consumer\njobs:\n  new-cross-consumer:\n    env:\n" +
    "      PLAN9ASM_CROSS_EXEC: '1'\n    steps:\n      - run: go run ./cmd/plan9asmtest\n";
  const caller = workflow + '\n  new-reusable-consumer:\n' +
    '    uses: ./.github/workflows/new-consumer.yml\n';
  const fixture = source => name => name === 'go-ci.yml' ? caller
    : name === 'new-consumer.yml' ? source : readWorkflow(name);
  assert.throws(() => requireFormalRuntimeDependencies(fixture(consumer)),
    /exactly one verified Node setup/);
  const guarded = consumer.replace('    steps:\n', '    steps:\n' +
    nodeStep(jobBody(workflow, 'cross-runtime')));
  assert.deepEqual(requireFormalRuntimeDependencies(fixture(guarded)).get('new-consumer.yml'),
    ['new-cross-consumer']);
});

for (const [file, jobs] of Object.entries(roles)) {
  const workflow = fs.readFileSync('.github/workflows/' + file, 'utf8');
  test(file + ' preserves every required verified Node role and its setup deadline', () => {
    assert.equal((workflow.match(/uses: \.\/\.github\/actions\/setup-node22$/gm) || []).length, jobs.length);
    for (const name of jobs) nodeStep(jobBody(workflow, name));
  });
  test(file + ' rejects missing, skipped, duplicate, ambient or unbounded runtime setup', () => {
    for (const name of jobs) {
      const body = jobBody(workflow, name), step = nodeStep(body);
      for (const replacement of [
        '', step + step,
        step.replace('uses: ./.github/actions/setup-node22', 'uses: actions/setup-node@v6'),
        step.replace('timeout-minutes: 10', 'timeout-minutes: 60'),
        step.replace('timeout-minutes: 10', 'if: false\n        timeout-minutes: 10'),
        step.replace('timeout-minutes: 10', 'continue-on-error: true\n        timeout-minutes: 10'),
        ...(step.includes('      - uses:')
          ? [step.replace('      - uses:', '      - if: false\n        uses:')] : []),
        step + '        uses: actions/setup-node@v6\n',
        step + "        with:\n          node-version: '22'\n",
      ]) {
        assert.notEqual(replacement, step, 'negative control must change its actual setup');
        assert.throws(() => nodeStep(body.replace(step, replacement)), undefined, name);
      }
    }
  });
}

test('policy checks execute only after their own verified Node installation', () => {
  for (const file of ['go-ci.yml', 'runtime-integration.yml']) {
    const body = jobBody(fs.readFileSync('.github/workflows/' + file, 'utf8'), 'ci_policy');
    const setup = nodeStep(body);
    assert.ok(body.indexOf(setup) < body.indexOf('run: node --test '));
  }
});
