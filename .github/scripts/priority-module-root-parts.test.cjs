const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const {requireJobNeeds} = require('./workflow-needs.cjs');

const workflow = fs.readFileSync(
  path.join(__dirname, '../workflows/go-ci.yml'), 'utf8',
);
const script = fs.readFileSync(
  path.join(__dirname, '../../scripts/test-module-ci.sh'), 'utf8',
);

function job(name, source = workflow) {
  const marker = `\n  ${name}:\n`;
  const start = source.indexOf(marker);
  assert.notEqual(start, -1, `missing job ${name}`);
  const body = source.slice(start + marker.length);
  const end = body.search(/^  [a-zA-Z][a-zA-Z0-9_-]*:\s*$/m);
  return end < 0 ? body : body.slice(0, end);
}

function step(body, name) {
  const marker = `      - name: ${name}\n`;
  const start = body.indexOf(marker);
  assert.notEqual(start, -1, `missing step ${name}`);
  const end = body.indexOf('\n      - name:', start + marker.length);
  return body.slice(start, end < 0 ? body.length : end);
}

test('every Unix root owner uses one two-shard wave with complete flavor-specific roles', () => {
  for (const name of ['test', 'race', 'coverage']) {
    const count = name === 'race' ? 32 : 16;
    const roles = [
      ...Array.from({ length: count }, (_, index) => `root-${index}`),
      'profile', 'other',
    ];
    const body = job(name);
    const match = body.match(/^        module-role: \[([^\]]+)\]$/m);
    assert.ok(match, `${name}: missing explicit module scheduling roles`);
    assert.deepEqual(match[1].split(',').map(value => value.trim()), roles);

    const mappings = Array.from(body.matchAll(
      /^          - \{module-role: (root-\d+|profile|other), module-owner: ([012]), root-partition: (-?\d+)\}$/gm,
    ), ([, role, owner, part]) => [role, Number(owner), Number(part)]);
    assert.deepEqual(mappings, [
      ...Array.from({ length: count }, (_, index) => [`root-${index}`, 0, index]),
      ['profile', 1, -1],
      ['other', 2, -1],
    ], `${name}: role mapping repeats or loses package/shard ownership`);
    assert.doesNotMatch(body, /^        module-owner: \[/m,
      `${name}: Cartesian ownership repeats profile/rest`);
    assert.match(body, /^      fail-fast: false$/m);
    assert.doesNotMatch(body, /max-parallel:|continue-on-error:/);
  }
});

test('root job fanout retains original workers, per-command and job budgets', () => {
  assert.match(script, /test\) timeout=45m ;;/);
  assert.match(script, /race\) timeout=60m; flags=\(-race\); root_partitions=32; shards=64 ;;/);
  assert.match(script, /coverage\) timeout=45m; flags=\(-coverprofile=coverage-root\.out\) ;;/);
  assert.match(script, /-shards=\$shards -workers=2/);
  assert.match(script, /GOMAXPROCS=2/);
  for (const [name, minutes] of [['test', 60], ['race', 75], ['coverage', 60]]) {
    assert.match(job(name), new RegExp(`^    timeout-minutes: ${minutes}$`, 'm'));
  }
  assert.match(job('module-completion'), /^    timeout-minutes: 30$/m);
});

test('executor and completion both request the same explicit root partition count', () => {
  assert.match(script, /^root_partitions=16$/m);
  assert.match(script, /-module-root-partitions=\$root_partitions/);
  assert.match(script, /-module-root-partition=\$4/);
  assert.match(script, /\[\[ \$# != 4/);
  for (const [name, flavor, title] of [
    ['test', 'test', 'Go test (Ubuntu)'],
    ['race', 'race', 'Go test (race)'],
    ['coverage', 'coverage', 'Go test with coverage'],
  ]) {
    assert.match(step(job(name), title), new RegExp(
      `bash scripts/test-module-ci\\.sh ${flavor} execute \\$\\{\\{ matrix\\.module-owner \\}\\} \\$\\{\\{ matrix\\.root-partition \\}\\}`,
    ));
  }
  assert.match(step(job('module-completion'), 'Check complete actual module inventory and coverage'),
    /bash scripts\/test-module-ci\.sh \$\{\{ matrix\.flavor \}\} complete/);
});

test('actual shell dispatch validates flavor-specific part bounds before launching Go', t => {
  // This is only an argument-transport fixture, never compiler/test evidence.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'module-ci-args-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(path.join(directory, 'go'),
    '#!/usr/bin/env bash\nprintf "%s\\n" SYNTHETIC_GO "$@"\n', { mode: 0o700 });
  const run = (...args) => spawnSync('bash', [
    path.join(__dirname, '../../scripts/test-module-ci.sh'), ...args,
  ], {
    cwd: directory,
    env: { ...process.env, PATH: directory + path.delimiter + process.env.PATH, GOFLAGS: '' },
    encoding: 'utf8',
    timeout: 5000,
  });
  for (const [flavor, count, shards] of [['test', 16, 32], ['coverage', 16, 32], ['race', 32, 64]]) {
    for (const args of [['execute', '0', String(count - 1)], ['execute', '2', '-1'], ['complete']]) {
      const actual = run(flavor, ...args);
      assert.equal(actual.status, 0, actual.stderr || String(actual.error));
      const fields = actual.stdout.trim().split('\n');
      assert.equal(fields[0], 'SYNTHETIC_GO');
      assert.ok(fields.includes(`-module-root-partitions=${count}`));
      assert.ok(fields.includes(`-shards=${shards}`));
      assert.ok(fields.includes('-workers=2'));
    }
    for (const part of [String(count), '-1', '01', '1+1', '999999999999999999999']) {
      const actual = run(flavor, 'execute', '0', part);
      assert.equal(actual.status, 1, `${flavor}/${part}: ${actual.stderr}`);
      assert.doesNotMatch(actual.stdout, /SYNTHETIC_GO/);
    }
  }
});

test('each root part has an exact separate artifact and strict download destination', () => {
  for (const name of ['test', 'race', 'coverage']) {
    const body = job(name);
    assert.match(body, /name: module-(?:test|race|coverage)-.*\$\{\{ matrix\.module-role \}\}/);
    assert.match(body, /if-no-files-found: error/);
  }
  const aggregate = job('module-completion');
  for (let part = 0; part < 32; part++) {
    const download = step(aggregate, `Download root part ${part}`);
    assert.match(download, new RegExp(
      `^          name: module-\\$\\{\\{ matrix\\.flavor \\}\\}-\\$\\{\\{ matrix\\.go-version \\}\\}-root-${part}$`, 'm',
    ));
    assert.match(download, new RegExp(
      `^          path: _out/module-\\$\\{\\{ matrix\\.flavor \\}\\}-owners/owner-0000/part-${String(part).padStart(4, '0')}$`, 'm',
    ));
    if (part >= 16) {
      assert.match(download, /if: \$\{\{ !cancelled\(\) && matrix\.flavor == 'race' \}\}/);
    } else {
      assert.doesNotMatch(download, /matrix\.flavor ==/);
    }
  }
  assert.match(step(aggregate, 'Download profile owner'), /-profile$/m);
  assert.match(step(aggregate, 'Download remaining-package owner'), /-other$/m);
  assert.doesNotMatch(aggregate, /merge-multiple:|pattern:/);
  requireJobNeeds(workflow, 'module-completion', ['test', 'nested-cli', 'race', 'coverage', 'nested-cli-coverage']);
  assert.match(aggregate, /^    if: \$\{\{ !cancelled\(\) \}\}$/m);
});

test('owner-two numerical fixture runs once and CLIs have independent complete modules', () => {
  const body = job('test');
  assert.match(step(body, 'Required exact downloaded AMD64 numerical fixture'), /matrix\.module-owner == 2/);
  assert.doesNotMatch(body, /nested_modules|working-directory: cmd\/plan9asm/);
  requireJobNeeds(workflow, 'nested-cli', ['ci_policy']);
  assert.match(job('nested-cli'), /^        module: \[plan9asm, plan9asmll\]$/m);
  assert.doesNotMatch(body, /os: windows-latest/);
  assert.match(job('windows-module'), /uses: \.\/\.github\/workflows\/windows-module\.yml/);
  assert.match(body,
    /go-version: \['1\.27\.2', '1\.20\.x', '1\.26\.x', '1\.25\.x', '1\.24\.x', '1\.23\.x', '1\.22\.x', '1\.21\.x'\]/);
});

test('selected native CI remains a separate sixteen-owner serial protocol', () => {
  const body = job('cross-runtime');
  assert.match(body, /owner: \[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15\]/);
  assert.match(body, /-ci-owner \$\{\{ matrix.owner \}\} -shards 16 -timeout 20m/);
  assert.doesNotMatch(body, /module-root-partition|module-owner|(?:^|\s)-workers(?:=|\s)/);
});

test('Windows modules retain disjoint scheduling and complete coverage readback', () => {
  const body = job('windows-module');
  assert.match(body, /^    needs: ci_policy$/m);
  assert.match(body, /^      fail-fast: false$/m);
  assert.match(body, /^        module: \[root, plan9asm, plan9asmll\]$/m);
  assert.doesNotMatch(body, /max-parallel:|continue-on-error:/);

  const native = fs.readFileSync(path.join(__dirname, '../workflows/windows-module.yml'), 'utf8');
  const roots = job('root-parts', native);
  assert.match(roots, /inputs.module == 'root' && '\[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15\]' \|\| '\[0,1,2,3\]'/);
  assert.match(roots, /execute 0 \$\{\{ matrix.part \}\}/);
  const others = job('other-owners', native);
  assert.match(others, /owner: \[1, 2\]/);
  assert.match(others, /execute \$\{\{ matrix.owner \}\} -1/);
  for (const owner of [roots, others]) {
    assert.match(owner, /fail-fast: false/);
    assert.match(owner, /timeout-minutes: 60/);
    assert.match(owner, /if-no-files-found: error/);
    assert.doesNotMatch(owner, /max-parallel:|continue-on-error:|codecov-action/);
  }
  const complete = job('complete', native);
  requireJobNeeds(native, 'complete', ['root-parts', 'other-owners']);
  assert.match(complete, /^    if: \$\{\{ !cancelled\(\) \}\}$/m);
  assert.doesNotMatch(complete, /merge-multiple:|pattern:/);
  assert.deepEqual(Array.from(complete.matchAll(
    /^      - name: Download root part (\d+)$/gm,
  ), ([, part]) => Number(part)), Array.from({ length: 16 }, (_, part) => part));
  for (let part = 0; part < 16; part++) {
    const download = step(complete, `Download root part ${part}`);
    assert.match(download, new RegExp(`-root-${part}$`, 'm'));
    assert.match(download, new RegExp(`owner-0000/part-${String(part).padStart(4, '0')}$`, 'm'));
    if (part >= 4) assert.match(download, /if: \$\{\{ inputs.module == 'root' \}\}/);
    else assert.doesNotMatch(download, /if:/);
  }
  assert.match(step(complete, 'Download profile owner'), /owner-0001$/m);
  assert.match(step(complete, 'Download remaining-package owner'), /owner-0002$/m);
  assert.match(step(complete, 'Verify complete module and publish coverage'),
    /test-windows-module-ci.sh \$\{\{ inputs.module \}\} complete/);
  assert.match(step(complete, 'Upload verified complete Windows module coverage'),
    /files: \.\/coverage-windows-\$\{\{ inputs.module \}\}\.out/);
});

function windowsModuleShellFixture(t) {
  // Argument transport only; native Go execution is covered by the Windows
  // module fixture, not by this synthetic command.
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'windows-module-ci-args-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const tools = Object.fromEntries(['go', 'llvm', 'node', 'python', 'jq'].map(name => {
    const bin = path.join(directory, name, 'bin');
    fs.mkdirSync(bin, { recursive: true });
    return [name, bin];
  }));
  fs.writeFileSync(path.join(tools.go, 'go'), `#!/bin/bash
if [[ "$*" == 'env GOHOSTOS' ]]; then
  echo windows
elif [[ "$*" == 'env GOROOT' ]]; then
  printf '%s\\n' '${path.dirname(tools.go)}'
else
  printf 'SYNTHETIC_PATH=%s\\n' "$PATH"
  printf '%s\\n' SYNTHETIC_GO "$@"
fi
`, { mode: 0o700 });
  const commands = {
    [path.join(directory, 'cygpath')]: 'if [[ "$1" == -m ]]; then echo C:/fixture; else printf "%s\\n" "$2"; fi',
    [path.join(tools.llvm, 'llvm-config')]: `if [[ "$1" == --version ]]; then echo 22.1.8; else echo '${tools.llvm}'; fi`,
    [path.join(tools.node, 'node')]: `echo '${tools.node}'`,
    [path.join(tools.python, 'python')]: `echo '${tools.python}'`,
    [path.join(tools.jq, 'jq')]: 'exit 0',
  };
  for (const [file, body] of Object.entries(commands)) {
    fs.writeFileSync(file, `#!/usr/bin/env bash\n${body}\n`, { mode: 0o700 });
  }
  const environment = {};
  const runAmbient = (ambient, flags, ...args) => spawnSync('bash', [
    path.join(__dirname, '../../scripts/test-windows-module-ci.sh'), ...args,
  ], {
    cwd: directory,
    env: {
      ...process.env,
      PATH: [directory, ...Object.values(tools), ambient, process.env.PATH].join(path.delimiter),
      GOFLAGS: flags,
      LLVM_CONFIG: '',
      SYSTEMROOT: path.join(directory, 'Windows'),
      ...environment,
    },
    encoding: 'utf8',
    timeout: 5000,
  });
  return { directory, tools, environment, runAmbient, run: (flags, ...args) => runAmbient('', flags, ...args) };
}

test('Windows shell transports complete module roles and rejects hidden build flags', t => {
  const { directory, run } = windowsModuleShellFixture(t);
  for (const [module, parts, shards] of [['root', 16, 64], ['plan9asm', 4, 8], ['plan9asmll', 4, 8]]) {
    const rootRoles = Array.from({ length: parts }, (_, part) => ['execute', '0', String(part)]);
    for (const args of [...rootRoles, ['execute', '1', '-1'], ['execute', '2', '-1']]) {
      const actual = run('-tags=byollvm', module, ...args);
      assert.equal(actual.status, 0, actual.stderr || String(actual.error));
      const fields = actual.stdout.trim().split('\n');
      assert.ok(fields.includes(`-module-owner=${args[1]}`));
      assert.ok(fields.includes(`-module-root-partition=${args[2]}`));
      for (const field of ['-module', '-timeout=30m', '-workers=2', '-tags=byollvm',
        `-shards=${shards}`, `-module-root-partitions=${parts}`, `-coverprofile=C:/fixture/coverage-windows-${module}.out`]) {
        assert.ok(fields.includes(field), `missing ${field}: ${actual.stdout}`);
      }
      assert.doesNotMatch(actual.stdout, /-run[=\s]|-skip[=\s]/);
    }
    const invalidParts = [String(parts), '-1', '-0', '+1', '01', '08', '1+1', '999999999999999999999'];
    for (const args of [
      ...invalidParts.map(part => ['execute', '0', part]),
      ['execute', '1', '0'], ['complete', '0'],
    ]) {
      const actual = run('-tags=byollvm', module, ...args);
      assert.equal(actual.status, 1, `${module}/${args}: ${actual.stderr}`);
      assert.doesNotMatch(actual.stdout, /SYNTHETIC_GO/);
    }
    const missing = run('-tags=byollvm', module, 'complete');
    assert.equal(missing.status, 1, 'completion without an actual profile must fail');
    fs.writeFileSync(path.join(directory, `coverage-windows-${module}.out`), 'fixture\n');
    const complete = run('-tags=byollvm', module, 'complete');
    assert.equal(complete.status, 0, complete.stderr);
    assert.match(complete.stdout, new RegExp(`-verify-module=_out/windows-module-${module}-owners`));
  }
  for (const flags of ['', '-tags=foreign', '-tags=byollvm -run=TestOnly']) {
    const actual = run(flags, 'root', 'execute', '0', '0');
    assert.equal(actual.status, 1, actual.stderr);
    assert.doesNotMatch(actual.stdout, /SYNTHETIC_GO/);
  }
});

test('Windows module execution and aggregation exclude ambient Git and WSL paths', t => {
  const { directory, tools, runAmbient } = windowsModuleShellFixture(t);
  const paths = [];
  for (const [git, wsl] of [['ucrt64', true], ['mingw64', false]]) {
    const ambient = [path.join(directory, 'Git', git, 'bin')];
    if (wsl) ambient.push(path.join(directory, 'WSL'));
    for (const role of [['execute', '0', '0'], ['complete']]) {
      fs.writeFileSync(path.join(directory, 'coverage-windows-root.out'), 'fixture\n');
      const actual = runAmbient(ambient.join(path.delimiter), '-tags=byollvm', 'root', ...role);
      assert.equal(actual.status, 0, actual.stderr);
      const observed = actual.stdout.split('\n').find(line => line.startsWith('SYNTHETIC_PATH='));
      assert.ok(observed, 'the actual driver did not reach the synthetic command');
      paths.push(observed.slice('SYNTHETIC_PATH='.length));
    }
  }
  assert.equal(new Set(paths).size, 1, 'cross-owner tool search still depends on the hosted image');
  const selected = paths[0].split(path.delimiter);
  for (const bin of Object.values(tools)) assert.ok(selected.includes(bin), `lost selected ${bin}`);
  assert.doesNotMatch(paths[0], /ucrt64|mingw64|WSL/);
  assert.deepEqual(selected, [
    tools.go, tools.llvm, tools.node, tools.python, tools.jq,
    '/cmd', '/usr/bin', path.join(directory, 'Windows', 'System32'), path.join(directory, 'Windows'),
  ]);
});

test('Windows module tool selection fails without falling back from explicit LLVM', t => {
  const { directory, tools, environment, run } = windowsModuleShellFixture(t);
  const configured = path.join(directory, 'explicit-llvm-config');
  environment.LLVM_CONFIG = configured;
  for (const version of ['23.1.0', '21.1.8', '', '22.1.8\nforeign']) {
    fs.writeFileSync(configured, `#!/usr/bin/env bash\nprintf '%s\\n' '${version}'\n`, { mode: 0o700 });
    const actual = run('-tags=byollvm', 'root', 'execute', '0', '0');
    assert.equal(actual.status, 1, actual.stderr);
    assert.match(actual.stderr, /selected LLVM 22/);
    assert.doesNotMatch(actual.stdout, /SYNTHETIC_GO/);
  }
  environment.LLVM_CONFIG = path.join(directory, 'missing-llvm-config');
  const missing = run('-tags=byollvm', 'root', 'execute', '0', '0');
  assert.notEqual(missing.status, 0);
  assert.doesNotMatch(missing.stdout, /SYNTHETIC_GO/);
  environment.LLVM_CONFIG = '';
  for (const name of ['node', 'python']) {
    const file = path.join(tools[name], name);
    const original = fs.readFileSync(file);
    fs.writeFileSync(file, '#!/usr/bin/env bash\nexit 17\n', { mode: 0o700 });
    const actual = run('-tags=byollvm', 'root', 'execute', '0', '0');
    assert.equal(actual.status, 1, actual.stderr);
    assert.match(actual.stderr, /one nonempty path/);
    assert.doesNotMatch(actual.stdout, /SYNTHETIC_GO/);
    fs.writeFileSync(file, original, { mode: 0o700 });
  }
});
