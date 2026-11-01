'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {jobBody, jobNeeds, requireJobNeeds} = require('./workflow-needs.cjs');
const {requireNode22Setup} = require('./node22-setup.cjs');

const workflow = fs.readFileSync(path.join(__dirname, '../workflows/go-ci.yml'), 'utf8');
const nested = fs.readFileSync(path.join(__dirname, '../workflows/linux-cli-module.yml'), 'utf8');
const versions = ['1.24.x', '1.25.x', '1.26.x', '1.27.2'];
const modules = ['plan9asm', 'plan9asmll'];
const compilerInstall = 'bash scripts/install-ci-llvm22-ubuntu.sh ' +
  'gcc-i686-linux-gnu libc6-dev-i386-cross gcc-aarch64-linux-gnu';

function steps(body) {
  return body.split(/(?=^      - )/m).slice(1);
}

function step(body, title) {
  const selected = steps(body).filter(item => item.startsWith(`      - name: ${title}\n`));
  assert.equal(selected.length, 1, 'one actual step required: ' + title);
  return selected[0];
}

function matrixValues(body, key) {
  const values = [...body.matchAll(new RegExp(`^        ${key}: \\[([^\\]]+)\\]$`, 'gm'))];
  assert.equal(values.length, 1, 'one complete matrix axis required: ' + key);
  return values[0][1].split(',').map(value => value.trim().replace(/^'(.*)'$/, '$1'));
}

function requireIndependentCLI(source) {
  const body = jobBody(source, 'nested-cli');
  assert.deepEqual(jobNeeds(source, 'nested-cli'), ['ci_policy']);
  assert.doesNotMatch(body, /^    if:|continue-on-error:|max-parallel:/m);
  assert.match(body, /^      fail-fast: false$/m);
  assert.deepEqual(matrixValues(body, 'go-version'), versions);
  assert.deepEqual(matrixValues(body, 'module'), modules);
  assert.doesNotMatch(body, /^        (?:include|exclude):|^    steps:|\bgo test\b/m);
  assert.match(body, /^    uses: \.\/\.github\/workflows\/linux-cli-module\.yml$/m);
  assert.match(body, /^      module: \$\{\{ matrix\.module \}\}$/m);
  assert.match(body, /^      go-version: \$\{\{ matrix\.go-version \}\}$/m);
  assert.match(body, /^      flavor: test$/m);
  assert.doesNotMatch(body, /scripts\/test-module-ci\.sh|Required exact downloaded/);
  requireJobNeeds(source, 'module-completion', ['test', 'nested-cli', 'race', 'coverage', 'nested-cli-coverage']);
  assert.match(jobBody(source, 'module-completion'), /^    if: \$\{\{ !cancelled\(\) \}\}$/m,
    'completion must still collect original owners after a failed CLI job');
}

function requireCLITools(source) {
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
    assert.ok(compiler.includes(`        run: ${compilerInstall}\n`));
    assert.match(compiler, /^        timeout-minutes: 14$/m);
    const qemu = step(body, 'Install required execution runtimes');
    assert.match(qemu, /^        run: bash scripts\/install-ci-qemu\.sh$/m);
    assert.match(qemu, /^        timeout-minutes: 5$/m);
    const node = step(body, 'Setup required wasm execution runtime');
    requireNode22Setup(node);
    for (const item of [checkout, setup, compiler, qemu, node]) {
      assert.doesNotMatch(item, /^        if:|continue-on-error:|\|\|\s*true/m);
      assert.ok(body.indexOf(item) < body.indexOf('        run: bash scripts/test-linux-cli-module-ci.sh '),
        'every CLI dependency must be installed before execution');
    }
    assert.ok(body.indexOf(qemu) < body.indexOf(node), 'retain QEMU/Node PATH provisioning order');
  }
}

function requireOriginalOtherOwner(source) {
  const body = jobBody(source, 'test');
  assert.match(body, /^    timeout-minutes: 60$/m);
  assert.match(step(body, 'Go test (Ubuntu)'),
    /^        run: bash scripts\/test-module-ci\.sh test execute \$\{\{ matrix\.module-owner \}\} \$\{\{ matrix\.root-partition \}\}$/m);
  assert.doesNotMatch(body, /nested_modules|working-directory: cmd\/plan9asm|Go test \(cmd\/plan9asm/,
    'remaining-package owners cannot serialize complete CLI suites');
  const numerical = step(body, 'Required exact downloaded AMD64 numerical fixture');
  assert.match(numerical,
    /^        if: runner\.os == 'Linux' && matrix\.go-version == '1\.27\.2' && matrix\.module-owner == 2$/m);
  assert.match(numerical, /^        shell: bash$/m);
  assert.match(numerical, /^          set -euo pipefail$/m);
  assert.match(numerical, /^          test "\$\(go env GOHOSTOS\)\/\$\(go env GOHOSTARCH\)" = linux\/amd64$/m);
  assert.match(numerical, /^          scope='\^TestAMD64DownloadedFixedLocalLLVM22Numerical\$'$/m);
  assert.match(numerical,
    /^          go test \.\/gotoolprofile -list="\$scope" \| grep -Fx 'TestAMD64DownloadedFixedLocalLLVM22Numerical'$/m);
  assert.match(numerical, /^          go test \.\/gotoolprofile -run="\$scope" -count=1 -timeout=10m$/m);
}

test('both complete CLIs own independent jobs for every supported nested SDK', () => {
  requireIndependentCLI(workflow);
});

test('every independent CLI owner retains its complete tool and execution runtimes', () => {
  requireCLITools(nested);
});

test('root other owner retains the exact numerical fixture without serial CLI suites', () => {
  requireOriginalOtherOwner(workflow);
});

test('CLI ownership rejects reduced matrices, serial scheduling and weakened success gates', () => {
  requireIndependentCLI(workflow);
  const body = jobBody(workflow, 'nested-cli');
  for (const [before, after] of [
    ["'1.24.x', ", ''],
    ["'1.25.x', ", ''],
    ["'1.26.x', ", ''],
    ["'1.27.2'", "'1.27.x'"],
    ['module: [plan9asm, plan9asmll]', 'module: [plan9asm]'],
    ['module: [plan9asm, plan9asmll]', 'module: [plan9asmll]'],
    ['fail-fast: false', 'fail-fast: true'],
    ['fail-fast: false', 'fail-fast: false\n      max-parallel: 1'],
    ['needs: ci_policy', 'needs: test'],
    ['linux-cli-module.yml', 'windows-module.yml'],
    ['module: ${{ matrix.module }}', 'module: plan9asm'],
    ['go-version: ${{ matrix.go-version }}', "go-version: '1.27.2'"],
    ['flavor: test', 'flavor: coverage'],
  ]) {
    const changed = body.replace(before, () => after);
    assert.notEqual(changed, body, 'ownership mutation must change its actual job: ' + before);
    assert.throws(() => requireIndependentCLI(workflow.replace(body, () => changed)), undefined, before);
  }
  const complete = jobBody(workflow, 'module-completion');
  const required = ['test', 'nested-cli', 'race', 'coverage', 'nested-cli-coverage'];
  for (const gate of required) {
    const reduced = required.filter(name => name !== gate);
    const changed = complete.replace(/^    needs:.*$/m, '    needs: [' + reduced.join(', ') + ']');
    assert.throws(() => requireIndependentCLI(workflow.replace(complete, changed)), undefined, gate);
  }
  const skipped = complete.replace('if: ${{ !cancelled() }}', 'if: success()');
  assert.notEqual(skipped, complete);
  assert.throws(() => requireIndependentCLI(workflow.replace(complete, skipped)));
});

test('CLI tool policies reject missing infrastructure and skipped setup', () => {
  requireCLITools(nested);
  for (const name of ['root-parts', 'complete']) {
    const body = jobBody(nested, name);
    for (const [before, after] of [
      [' gcc-i686-linux-gnu', ''],
      [' libc6-dev-i386-cross', ''],
      [' gcc-aarch64-linux-gnu', ''],
      ['install-ci-llvm22-ubuntu.sh', 'install-llvm23.sh'],
      ['install-ci-qemu.sh', 'install-unpinned-qemu.sh'],
      ['uses: ./.github/actions/setup-node22', 'uses: actions/setup-node@v6'],
      ['go-version: ${{ inputs.go-version }}', "go-version: '1.27.2'"],
      ['        run: ' + compilerInstall, '        if: false\n        run: ' + compilerInstall],
    ]) {
      const changed = body.replace(before, () => after);
      assert.notEqual(changed, body, 'tool mutation must change its actual job: ' + before);
      assert.throws(() => requireCLITools(nested.replace(body, () => changed)), undefined, before);
    }
  }
});
