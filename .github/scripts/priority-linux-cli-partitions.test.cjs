'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const {spawnSync} = require('node:child_process');
const test = require('node:test');
const {jobBody, jobNeeds} = require('./workflow-needs.cjs');

const root = path.join(__dirname, '../..');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/go-ci.yml'), 'utf8');
function optional(name) {
  return fs.existsSync(path.join(root, name)) ? fs.readFileSync(path.join(root, name), 'utf8') : '';
}
const nested = optional('.github/workflows/linux-cli-module.yml');
const driver = optional('scripts/test-linux-cli-module-ci.sh');
const route = "${{ github.repository_owner == 'xgo-dev' && " +
  "fromJSON('[\"qiniu\", \"ubuntu-24.04-large\"]') || 'ubuntu-latest' }}";
const identity = 'linux-cli-${{ inputs.module }}-${{ inputs.go-version }}-${{ inputs.flavor }}';
const directory = '_out/linux-cli-${{ inputs.module }}-${{ inputs.flavor }}';

function step(body, title) {
  const selected = body.split(/(?=^      - )/m).filter(item =>
    item.startsWith('      - name: ' + title + '\n'));
  assert.equal(selected.length, 1, 'one actual step: ' + title);
  return selected[0];
}

function requireCalls(source) {
  for (const [name, flavor, version] of [
    ['nested-cli', 'test', '${{ matrix.go-version }}'],
    ['nested-cli-coverage', 'coverage', "'1.27.2'"],
  ]) {
    const body = jobBody(source, name);
    assert.deepEqual(jobNeeds(source, name), ['ci_policy']);
    assert.match(body, /^    uses: \.\/\.github\/workflows\/linux-cli-module\.yml$/m,
      name + ': one serial full-package command still exhausts its shared binary deadline');
    assert.ok(body.includes('      module: ${{ matrix.module }}\n'));
    assert.ok(body.includes('      go-version: ' + version + '\n'));
    assert.ok(body.includes('      flavor: ' + flavor + '\n'));
    assert.match(body, /^        module: \[plan9asm, plan9asmll\]$/m);
    assert.match(body, /^      fail-fast: false$/m);
    assert.doesNotMatch(body, /^    if:|continue-on-error:|max-parallel:|\bgo test\b|^    steps:/m);
  }
  assert.match(jobBody(source, 'nested-cli'),
    /^        go-version: \['1\.24\.x', '1\.25\.x', '1\.26\.x', '1\.27\.2'\]$/m);
}

function requireRoles(source) {
  for (const input of ['module', 'go-version', 'flavor']) {
    assert.ok(source.includes('      ' + input + ':\n        required: true\n        type: string\n'));
  }
  for (const name of ['root-parts', 'complete']) {
    const body = jobBody(source, name);
    assert.ok(body.includes('    runs-on: ' + route + '\n'), name + ': same explicit runner route');
    assert.doesNotMatch(body, /continue-on-error:|max-parallel:|\|\|\s*true/);
    assert.match(body, new RegExp('^    timeout-minutes: ' + (name === 'complete' ? 30 : 60) + '$', 'm'));
    const setup = step(body, 'Setup Go');
    assert.match(setup, /^        timeout-minutes: 10$/m);
    assert.match(setup, /^        uses: \.\/\.github\/actions\/setup-go$/m);
    assert.match(setup, /^          go-version: \$\{\{ inputs\.go-version \}\}$/m);
    assert.doesNotMatch(setup, /^          cache:/m);
    const compiler = step(body, 'Install LLVM 22 and cross compilers');
    assert.match(compiler, /^        timeout-minutes: 14$/m);
    assert.match(compiler, /^        run: bash scripts\/install-ci-llvm22-ubuntu\.sh gcc-i686-linux-gnu libc6-dev-i386-cross gcc-aarch64-linux-gnu$/m);
    const qemu = step(body, 'Install required execution runtimes');
    assert.match(qemu, /^        timeout-minutes: 5$/m);
    assert.match(qemu, /^        run: bash scripts\/install-ci-qemu\.sh$/m);
    const node = step(body, 'Setup required wasm execution runtime');
    assert.match(node, /^        timeout-minutes: 10$/m);
    assert.match(node, /^        uses: \.\/\.github\/actions\/setup-node22$/m);
    assert.doesNotMatch(node, /node-version:|uses: actions\/setup-node@/);
    for (const item of [setup, compiler, qemu, node]) {
      assert.doesNotMatch(item, /^        if:|continue-on-error:/m);
    }
    assert.ok(body.indexOf(compiler) < body.indexOf(qemu));
    assert.ok(body.indexOf(qemu) < body.indexOf(node));
  }
  const roots = jobBody(source, 'root-parts');
  assert.doesNotMatch(roots, /^    if:/m);
  assert.match(roots, /^        part: \[0, 1, 2, 3\]$/m);
  assert.match(roots, /^      fail-fast: false$/m);
  assert.match(roots, /test-linux-cli-module-ci\.sh \$\{\{ inputs\.module \}\} \$\{\{ inputs\.flavor \}\} execute 0 \$\{\{ matrix\.part \}\}/);
  assert.doesNotMatch(step(roots, 'Execute disjoint root assignment'), /^        if:/m);
  const retain = step(roots, 'Retain actual root evidence');
  assert.match(retain, /^        if: \$\{\{ always\(\) \}\}$/m);
  assert.match(retain, /^        uses: actions\/upload-artifact@v6$/m);
  assert.match(retain, /^          if-no-files-found: error$/m);
  assert.ok(retain.includes('          name: ' + identity + '-root-${{ matrix.part }}\n'));
  assert.ok(retain.includes('          path: ' + directory + '-root-${{ matrix.part }}/\n'));
  for (const [title, owner] of [['profile', 1], ['remaining-package', 2]]) {
    const execution = step(roots, 'Execute complete ' + title + ' owner');
    assert.match(execution, /^        if: \$\{\{ !cancelled\(\) && matrix\.part == 0 \}\}$/m);
    assert.ok(execution.includes('        run: bash scripts/test-linux-cli-module-ci.sh ' +
      '${{ inputs.module }} ${{ inputs.flavor }} execute ' + owner + ' -1\n'));
    const artifact = step(roots, 'Retain actual ' + title + ' evidence');
    assert.match(artifact, /^        if: \$\{\{ always\(\) && matrix\.part == 0 \}\}$/m);
    assert.match(artifact, /^        uses: actions\/upload-artifact@v6$/m);
    assert.match(artifact, /^          if-no-files-found: error$/m);
    assert.ok(artifact.includes('          name: ' + identity + '-owner-' + owner + '\n'));
    assert.ok(artifact.includes('          path: ' + directory + '-owner-' + owner + '/\n'));
  }
  const complete = jobBody(source, 'complete');
  assert.deepEqual(jobNeeds(source, 'complete'), ['root-parts']);
  assert.match(complete, /^    if: \$\{\{ !cancelled\(\) \}\}$/m);
  for (let part = 0; part < 4; part++) {
    const download = step(complete, 'Download root part ' + part);
    assert.match(download, /^        if: \$\{\{ !cancelled\(\) \}\}$/m);
    assert.match(download, /^        uses: actions\/download-artifact@v8$/m);
    assert.ok(download.includes('          name: ' + identity + '-root-' + part + '\n'));
    assert.ok(download.includes('          path: ' + directory + '-owners/owner-0000/part-000' + part + '\n'));
  }
  for (const [title, owner] of [['Download profile owner', 1], ['Download remaining-package owner', 2]]) {
    const download = step(complete, title);
    assert.match(download, /^        if: \$\{\{ !cancelled\(\) \}\}$/m);
    assert.match(download, /^        uses: actions\/download-artifact@v8$/m);
    assert.ok(download.includes('          name: ' + identity + '-owner-' + owner + '\n'));
    assert.ok(download.includes('          path: ' + directory + '-owners/owner-000' + owner + '\n'));
  }
  const verify = step(complete, 'Verify complete CLI module');
  assert.match(verify, /^        if: \$\{\{ !cancelled\(\) \}\}$/m);
  assert.match(verify, /test-linux-cli-module-ci\.sh \$\{\{ inputs\.module \}\} \$\{\{ inputs\.flavor \}\} complete/);
  assert.doesNotMatch(complete, /merge-multiple:|pattern:|codecov\/codecov-action/);
  const success = step(complete, 'Require successful CLI owners');
  assert.match(success, /^        if: \$\{\{ !cancelled\(\) \}\}$/m);
  assert.match(success, /^        run: test '\$\{\{ needs\.root-parts\.result \}\}' = success$/m);
  const summary = step(complete, 'Show complete CLI coverage');
  assert.match(summary, /^        if: inputs\.flavor == 'coverage'$/m);
  assert.match(summary, /^        run: go tool cover -func=coverage-\$\{\{ inputs\.module \}\}\.out \| tail -n 1$/m);
  assert.match(summary, /^        working-directory: cmd\/\$\{\{ inputs\.module \}\}$/m);
  assert.ok(complete.indexOf(verify) < complete.indexOf(summary));
  assert.ok(complete.indexOf(summary) < complete.indexOf(success));
}

function requireDriver(source) {
  for (const text of ['plan9asm|plan9asmll)', 'test) flags=()',
    'coverage) flags=("-coverprofile=coverage-$module.out")',
    '-module', '-dir=cmd/$module', '-shards=8', '-workers=2', '-timeout=30m',
    '-module-root-partitions=4', '-verify-module=_out/linux-cli-$module-$flavor-owners',
    'GOFLAGS= GOENV=off GOWORK=off GOTOOLCHAIN=local GOMAXPROCS=2',
    'go run ./cmd/plan9asmtest']) {
    assert.ok(source.includes(text), 'complete original module protocol: ' + text);
  }
  assert.doesNotMatch(source, /(?:^|\s)-(?:run|skip|short|list)(?:=|\s)|timeout=(?:45m|60m)|\|\|\s*true/);
}

test('all CLI SDK/module invocations require strict complete partition workflows', () => requireCalls(workflow));
test('each Linux CLI fragment and fresh aggregate owns exact tools, budgets and evidence', () => requireRoles(nested));
test('Linux CLI driver retains full inventory, original flags and exact module protocol', () => requireDriver(driver));

test('closed ownership rejects missing pieces, skipped collection and borrowed coverage', () => {
  requireCalls(workflow);
  requireRoles(nested);
  requireDriver(driver);
  for (const [before, after] of [
    ['part: [0, 1, 2, 3]', 'part: [0, 1, 2]'],
    ['execute 2 -1', 'execute 1 -1'],
    ['needs: root-parts', 'needs: unrelated'],
    ['    if: ${{ !cancelled() }}', '    if: success()'],
    ['timeout-minutes: 60', 'timeout-minutes: 90'],
    ['-root-3\n', '-root-2\n'],
    ['part-0003\n', 'part-0002\n'],
    ['uses: ./.github/actions/setup-node22', 'uses: actions/setup-node@v6'],
    ['timeout-minutes: 10', 'timeout-minutes: 30'],
    [' gcc-aarch64-linux-gnu', ''],
    [' gcc-i686-linux-gnu', ''],
    [' libc6-dev-i386-cross', ''],
    ['install-ci-qemu.sh', 'install-unpinned-qemu.sh'],
    ['install-ci-llvm22-ubuntu.sh', 'install-llvm23.sh'],
    [route, "'ubuntu-latest'"],
    [identity, 'linux-cli-wrong-module'],
    [directory + '-root-${{ matrix.part }}/', directory + '-all-roots/'],
    ["test '${{ needs.root-parts.result }}' = success", 'true'],
    ['!cancelled() && matrix.part == 0', 'success() && matrix.part == 0'],
    ['inputs.flavor == \'coverage\'', 'false'],
  ]) {
    const changed = nested.replace(before, () => after);
    assert.notEqual(changed, nested, 'negative control must affect the actual source: ' + before);
    assert.throws(() => requireRoles(changed), undefined, before);
  }
  for (const [before, after] of [
    ['-timeout=30m', '-timeout=45m'], ['-shards=8', '-shards=4'],
    ['-module-root-partitions=4', '-module-root-partitions=2'],
    ['-verify-module=', '-replay-unverified='],
    ['-dir=cmd/$module', '-dir=cmd/plan9asm'],
    ['go run ./cmd/plan9asmtest', 'go run ./cmd/plan9asmtest -run=TestOnly'],
    ['go run ./cmd/plan9asmtest', 'go run ./cmd/plan9asmtest -skip=TestSlow'],
    ['coverage-$module.out', 'coverage-root.out'],
  ]) {
    const changed = driver.replace(before, () => after);
    assert.notEqual(changed, driver);
    assert.throws(() => requireDriver(changed), undefined, before);
  }
});

test('actual Linux CLI shell transports every module/flavor/owner and rejects partial grammar', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'linux-cli-transport-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  // This is explicitly a shell transport fixture, not Go or instruction execution.
  fs.writeFileSync(path.join(directory, 'go'), '#!/bin/bash\n' +
    'printf "SYNTHETIC_ENV=%s/%s/%s/%s/%s\\n" "$GOFLAGS" "$GOENV" "$GOWORK" "$GOTOOLCHAIN" "$GOMAXPROCS"\n' +
    'printf "%s\\n" SYNTHETIC_GO "$@"\n', {mode: 0o700});
  const run = (...args) => spawnSync('bash', [path.join(root, 'scripts/test-linux-cli-module-ci.sh'), ...args], {
    cwd: directory,
    env: {...process.env, PATH: directory + path.delimiter + process.env.PATH, GOFLAGS: ''},
    encoding: 'utf8', timeout: 5000,
  });
  for (const module of ['plan9asm', 'plan9asmll']) {
    for (const flavor of ['test', 'coverage']) {
      const outputs = new Set();
      for (const [owner, part] of [['0', '0'], ['0', '1'], ['0', '2'], ['0', '3'], ['1', '-1'], ['2', '-1']]) {
        const actual = run(module, flavor, 'execute', owner, part);
        assert.equal(actual.status, 0, actual.stderr || String(actual.error));
        const fields = actual.stdout.trim().split('\n');
        assert.ok(fields.includes('SYNTHETIC_ENV=/off/off/local/2'));
        for (const field of ['run', './cmd/plan9asmtest', '-module', '-dir=cmd/' + module,
          '-module-owner=' + owner, '-module-root-partition=' + part, '-shards=8',
          '-workers=2', '-timeout=30m', '-module-root-partitions=4']) {
          assert.ok(fields.includes(field), 'actual driver lost ' + field);
        }
        assert.equal(fields.includes('-coverprofile=coverage-' + module + '.out'), flavor === 'coverage');
        const output = fields.filter(field => field.startsWith('-out='));
        assert.equal(output.length, 1);
        assert.ok(!outputs.has(output[0]), 'owners cannot share an output directory');
        outputs.add(output[0]);
      }
      if (flavor === 'coverage') {
        assert.equal(run(module, flavor, 'complete').status, 1, 'missing complete profile must fail');
        const profile = path.join(directory, 'cmd', module, 'coverage-' + module + '.out');
        fs.mkdirSync(path.dirname(profile), {recursive: true});
        fs.writeFileSync(profile, 'synthetic profile, not coverage evidence\n');
      }
      const complete = run(module, flavor, 'complete');
      assert.equal(complete.status, 0, complete.stderr);
      assert.ok(complete.stdout.includes('-verify-module=_out/linux-cli-' + module + '-' + flavor + '-owners\n'));
      for (const role of [
        ['execute', '0', '4'], ['execute', '0', '-1'], ['execute', '0', '01'],
        ['execute', '0', '+1'], ['execute', '0', '1+1'], ['execute', '3', '-1'],
        ['execute', '1', '0'], ['execute', '2', '0'], ['execute', '0'],
        ['execute', '0', '0', 'extra'], ['complete', '0'], ['unknown'],
      ]) {
        const invalid = run(module, flavor, ...role);
        assert.equal(invalid.status, 1, [module, flavor, ...role].join('/'));
        assert.doesNotMatch(invalid.stdout, /SYNTHETIC_GO/);
      }
    }
  }
  for (const args of [['root', 'test', 'complete'], ['plan9asm', 'race', 'complete']]) {
    const invalid = run(...args);
    assert.equal(invalid.status, 1);
    assert.doesNotMatch(invalid.stdout, /SYNTHETIC_GO/);
  }
  const flags = spawnSync('bash', [path.join(root, 'scripts/test-linux-cli-module-ci.sh'),
    'plan9asmll', 'test', 'execute', '0', '0'], {
    cwd: directory, env: {...process.env, PATH: directory + path.delimiter + process.env.PATH, GOFLAGS: '-run=Only'},
    encoding: 'utf8', timeout: 5000,
  });
  assert.equal(flags.status, 1);
  assert.doesNotMatch(flags.stdout, /SYNTHETIC_GO/);
});
