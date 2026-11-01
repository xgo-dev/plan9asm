'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {jobBody, jobNeeds, requireJobNeeds} = require('./workflow-needs.cjs');
const {requireNode22Setup} = require('./node22-setup.cjs');

const workflow = fs.readFileSync(path.join(__dirname, '../workflows/go-ci.yml'), 'utf8');
const nested = fs.readFileSync(path.join(__dirname, '../workflows/linux-cli-module.yml'), 'utf8');
const driver = fs.readFileSync(path.join(__dirname, '../../scripts/test-linux-cli-module-ci.sh'), 'utf8');
const producer = 'nested-cli-coverage';
const required = ['test', 'nested-cli', 'race', 'coverage', producer];
const compilerInstall = 'bash scripts/install-ci-llvm22-ubuntu.sh ' +
  'gcc-i686-linux-gnu libc6-dev-i386-cross gcc-aarch64-linux-gnu';
const completeCondition = "        if: ${{ !cancelled() && matrix.flavor == 'coverage' }}";
const completeCommand = "        run: test '${{ needs['nested-cli-coverage'].result }}' = success";

function steps(body) {
  return body.split(/(?=^      - )/m).slice(1);
}

function step(body, title) {
  const selected = steps(body).filter(item => item.startsWith(`      - name: ${title}\n`));
  assert.equal(selected.length, 1, 'one actual step required: ' + title);
  return selected[0];
}

function requireIndependentOwners(source) {
  const body = jobBody(source, producer);
  assert.deepEqual(jobNeeds(source, producer), ['ci_policy']);
  assert.match(body, /^      fail-fast: false$/m);
  assert.doesNotMatch(body, /^    if:|continue-on-error:|max-parallel:|^    steps:/m);
  const axes = [...body.matchAll(/^        ([a-z-]+): \[([^\]]+)\]$/gm)];
  assert.deepEqual(axes.map(([, key, values]) => [key, values.split(',').map(value => value.trim())]),
    [['module', ['plan9asm', 'plan9asmll']]],
    'one independent current-SDK job for each complete CLI, not a serial module loop');
  assert.doesNotMatch(body, /^        (?:include|exclude):|\bgo test\b/m);
  assert.match(body, /^    uses: \.\/\.github\/workflows\/linux-cli-module\.yml$/m);
  assert.match(body, /^      module: \$\{\{ matrix\.module \}\}$/m);
  assert.match(body, /^      go-version: '1\.27\.2'$/m);
  assert.match(body, /^      flavor: coverage$/m);
  return body;
}

function requireCompleteCommands(source) {
  requireIndependentOwners(source);
  assert.ok(driver.includes('coverage) flags=("-coverprofile=coverage-$module.out")'));
  assert.ok(driver.includes('-module-root-partitions=4'));
  assert.ok(driver.includes('-verify-module=_out/linux-cli-$module-$flavor-owners'));
  assert.ok(driver.includes('-timeout=30m'));
  assert.doesNotMatch(driver, /(?:^|\s)-(?:run|skip|short|list)(?:=|\s)/m);
  const complete = jobBody(nested, 'complete');
  const summary = step(complete, 'Show complete CLI coverage');
  assert.match(summary, /^        if: inputs\.flavor == 'coverage'$/m);
  assert.match(summary, /^        run: go tool cover -func=coverage-\$\{\{ inputs\.module \}\}\.out \| tail -n 1$/m);
  assert.match(summary, /^        working-directory: cmd\/\$\{\{ inputs\.module \}\}$/m);
  assert.ok(complete.indexOf('Verify complete CLI module') < complete.indexOf(summary));
}

function requireTools(source) {
  for (const name of ['root-parts', 'complete']) {
    const body = jobBody(source, name);
    const checkout = step(body, 'Checkout');
    assert.match(checkout, /^        uses: actions\/checkout@v7$/m);
    const setup = step(body, 'Setup Go');
    assert.match(setup, /^        timeout-minutes: 10$/m);
    assert.match(setup, /^        uses: \.\/\.github\/actions\/setup-go$/m);
    assert.match(setup, /^          go-version: \$\{\{ inputs\.go-version \}\}$/m);
    assert.doesNotMatch(setup, /^          cache:/m);
    assert.doesNotMatch(body, /uses: actions\/setup-go@|go-version-file:|check-latest:/);
    const compiler = step(body, 'Install LLVM 22 and cross compilers');
    assert.ok(compiler.includes('        run: ' + compilerInstall + '\n'));
    assert.match(compiler, /^        timeout-minutes: 14$/m);
    const qemu = step(body, 'Install required execution runtimes');
    assert.match(qemu, /^        run: bash scripts\/install-ci-qemu\.sh$/m);
    assert.match(qemu, /^        timeout-minutes: 5$/m);
    const info = step(body, 'LLVM tools info');
    for (const command of ['command -v llc', 'llc --version', 'command -v clang', 'clang --version']) {
      assert.ok(info.includes('          ' + command + '\n'));
    }
    const node = step(body, 'Setup required wasm execution runtime');
    requireNode22Setup(node);
    for (const item of [checkout, setup, compiler, qemu, info, node]) {
      assert.doesNotMatch(item, /^        if:|continue-on-error:|\|\|\s*true/m);
      assert.ok(body.indexOf(item) < body.indexOf('        run: bash scripts/test-linux-cli-module-ci.sh '));
    }
    assert.ok(body.indexOf(qemu) < body.indexOf(node));
  }
}

function requireOriginalOwners(source) {
  for (const flavor of ['test', 'race', 'coverage']) {
    const body = jobBody(source, flavor);
    assert.doesNotMatch(body, /working-directory: cmd\/|coverage-plan9asm|nested_modules/,
      flavor + ': root/profile/rest owners must not serialize complete nested CLI suites');
  }
  const body = jobBody(source, 'coverage');
  assert.match(body, /^    timeout-minutes: 60$/m);
  assert.match(step(body, 'Go test with coverage'),
    /^        run: bash scripts\/test-module-ci\.sh coverage execute \$\{\{ matrix\.module-owner \}\} \$\{\{ matrix\.root-partition \}\}$/m);
  const evidence = step(body, 'Retain complete module coverage owner evidence');
  assert.match(evidence, /^        if: \$\{\{ !cancelled\(\) \}\}$/m);
  assert.match(evidence, /^          name: module-coverage-1\.27\.2-\$\{\{ matrix\.module-role \}\}$/m);
  assert.match(evidence, /^          path: _out\/module-coverage\/$/m);
  assert.match(evidence, /^          if-no-files-found: error$/m);
}

function requireCompletion(source) {
  requireJobNeeds(source, 'module-completion', required);
  const body = jobBody(source, 'module-completion');
  assert.match(body, /^    if: \$\{\{ !cancelled\(\) \}\}$/m);
  for (const title of ['Check complete actual module inventory and coverage',
    'Retain independent aggregate evidence']) {
    assert.match(step(body, title), /^        if: \$\{\{ !cancelled\(\) \}\}$/m);
  }
  const summary = step(body, 'Show complete module coverage');
  assert.match(summary, /^        if: matrix\.flavor == 'coverage'$/m);
  assert.match(summary, /^        run: go tool cover -func=coverage-root\.out \| tail -n 1$/m);
  const upload = step(body, 'Upload coverage to Codecov');
  assert.match(upload, /^        if: matrix\.flavor == 'coverage'$/m);
  assert.match(upload, /^        uses: codecov\/codecov-action@v7$/m);
  for (const field of ['use_oidc: true', 'files: ./coverage-root.out', 'disable_search: true',
    'flags: unittests', 'name: ubuntu-go1.27', 'fail_ci_if_error: false', 'verbose: true']) {
    assert.ok(upload.includes('          ' + field + '\n'));
  }
  assert.doesNotMatch(upload, /coverage-\$\{\{|coverage-plan9asm/,
    'nested modules are not main-module coverage inputs');
  const success = step(body, 'Require complete CLI coverage');
  assert.ok(success.includes(completeCondition + '\n'));
  assert.ok(success.includes(completeCommand + '\n'));
  assert.doesNotMatch(success, /continue-on-error:|\|\|\s*true/);
  assert.ok(body.indexOf(success) > body.indexOf(upload),
    'a failed CLI producer must not suppress the original root aggregate and upload');
}

test('both complete CLI coverage modules own independent current-SDK job budgets', () => {
  requireIndependentOwners(workflow);
  requireCompleteCommands(workflow);
});

test('independent CLI coverage retains exact Go, LLVM and required execution dependencies', () => {
  requireIndependentOwners(workflow);
  requireTools(nested);
});

test('root coverage no longer serializes CLI coverage and race has no invented CLI matrix', () => {
  requireOriginalOwners(workflow);
});

test('CLI coverage failure remains a completion failure after original root evidence collection', () => {
  requireCompletion(workflow);
});

test('CLI coverage policy rejects reduced, duplicated, serial, filtered or over-budget owners', () => {
  requireCompleteCommands(workflow);
  const body = jobBody(workflow, producer);
  for (const [before, after] of [
    ['module: [plan9asm, plan9asmll]', 'module: [plan9asm]'],
    ['module: [plan9asm, plan9asmll]', 'module: [plan9asmll]'],
    ['module: [plan9asm, plan9asmll]', 'module: [plan9asm, plan9asm]'],
    ['needs: ci_policy', 'needs: coverage'],
    ['fail-fast: false', 'fail-fast: true'],
    ['fail-fast: false', 'fail-fast: false\n      max-parallel: 1'],
    ['needs: ci_policy', 'needs: ci_policy\n    continue-on-error: true'],
    ['linux-cli-module.yml', 'windows-module.yml'],
    ['module: ${{ matrix.module }}', 'module: plan9asm'],
    ["go-version: '1.27.2'", "go-version: '1.27.x'"],
    ['flavor: coverage', 'flavor: test'],
  ]) {
    const changed = body.replace(before, () => after);
    assert.notEqual(changed, body, before);
    assert.throws(() => requireCompleteCommands(workflow.replace(body, () => changed)), undefined, before);
  }
});

test('CLI coverage dependencies cannot borrow skipped, missing or foreign tool installations', () => {
  requireTools(nested);
  for (const name of ['root-parts', 'complete']) {
    const body = jobBody(nested, name);
    for (const [before, after] of [
      ['go-version: ${{ inputs.go-version }}', "go-version: '1.27.2'"],
      [' gcc-i686-linux-gnu', ''],
      [' libc6-dev-i386-cross', ''],
      [' gcc-aarch64-linux-gnu', ''],
      ['install-ci-llvm22-ubuntu.sh', 'install-llvm23.sh'],
      ['install-ci-qemu.sh', 'install-unpinned-qemu.sh'],
      ['uses: ./.github/actions/setup-node22', 'uses: actions/setup-node@v6'],
      ['        run: ' + compilerInstall, '        if: false\n        run: ' + compilerInstall],
    ]) {
      const changed = body.replace(before, () => after);
      assert.notEqual(changed, body, before);
      assert.throws(() => requireTools(nested.replace(body, () => changed)), undefined, before);
    }
  }
});

test('CLI coverage completion rejects missing needs, skipped collection and borrowed success', () => {
  requireCompletion(workflow);
  const body = jobBody(workflow, 'module-completion');
  for (const gate of required) {
    const changed = body.replace(/^    needs:.*$/m,
      () => '    needs: [' + required.filter(name => name !== gate).join(', ') + ']');
    assert.notEqual(changed, body, gate);
    assert.throws(() => requireCompletion(workflow.replace(body, () => changed)), undefined, gate);
  }
  for (const [before, after] of [
    ['    if: ${{ !cancelled() }}', '    if: success()'],
    [completeCondition, "        if: matrix.flavor == 'coverage'"],
    [completeCondition, "        if: ${{ !cancelled() && matrix.flavor == 'test' }}"],
    [completeCommand, "        run: test '${{ needs['nested-cli'].result }}' = success"],
    [completeCommand, completeCommand + ' || true'],
    [completeCommand, '        run: true'],
  ]) {
    const changed = body.replace(before, () => after);
    assert.notEqual(changed, body, before);
    assert.throws(() => requireCompletion(workflow.replace(body, () => changed)), undefined, before);
  }
});
