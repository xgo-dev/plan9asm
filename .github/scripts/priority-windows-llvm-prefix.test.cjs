'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {test} = require('node:test');

const action = fs.readFileSync('.github/actions/setup-windows-llvm22/action.yml', 'utf8');
const publisherFile = path.resolve('.github/actions/publish-windows-llvm22/index.cjs');
function publisher() {
  assert.ok(fs.existsSync(publisherFile), 'successful attempts need one stable, guarded native publication');
  return require(publisherFile).publishPrefix;
}

function fixture(t, attempt = '1') {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'llvm22 prefix '));
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));
  const source = path.join(root, 'plan9asm-msys2-attempt-' + attempt, 'msys64', 'clang64');
  for (const relative of ['bin/llvm-config.exe', 'bin/clang.exe', 'bin/clang++.exe',
    'include/stdint.h', 'include/_mingw.h', 'lib/libkernel32.a', 'lib/clang/22/include/stddef.h']) {
    const file = path.join(source, relative);
    fs.mkdirSync(path.dirname(file), {recursive: true});
    fs.writeFileSync(file, 'synthetic transport input, not executable LLVM\n', {flag: 'wx'});
  }
  const target = path.join(root, 'plan9asm-llvm22');
  const commands = [];
  const run = (file, args, options) => {
    commands.push({file, args});
    const name = path.basename(file);
    if (name === 'powershell.exe') {
      assert.ok(args.join(' ').includes('ReparsePoint'));
      assert.ok(options.env.PLAN9ASM_LLVM22_CHECK);
      return '';
    }
    assert.ok(file.startsWith(target + path.sep) || file.startsWith(path.join(root, 'plan9asm-llvm22-proof') + path.sep));
    if (name === 'llvm-config.exe') {
      switch (args.join(' ')) {
        case '--version': return '22.1.8\r\n';
        case '--prefix': return target + '\r\n';
        case '--bindir': return path.join(target, 'bin') + '\n';
        case '--includedir': return path.join(target, 'include') + '\n';
        case '--libdir': return path.join(target, 'lib') + '\n';
        case '--cflags': return '-I' + path.join(target, 'include') + '\n';
        case '--cxxflags': return '-I' + path.join(target, 'include') + ' -std=c++17\n';
        case '--ldflags --libs all --system-libs': return '-L' + path.join(target, 'lib') + ' -lLLVM\n';
        default: assert.fail('unexpected real publisher query: ' + args.join(' '));
      }
    }
    if (name === 'clang.exe') {
      if (args.join(' ') === '--version') return 'clang version 22.1.8\nTarget: x86_64-w64-windows-gnu\n';
      if (args.join(' ') === '--print-resource-dir') return path.join(target, 'lib', 'clang', '22') + '\n';
      const output = args[args.indexOf('-o') + 1];
      assert.ok(output.startsWith(path.join(root, 'plan9asm-llvm22-proof') + path.sep));
      fs.writeFileSync(output, 'synthetic link result, never native execution\n', {flag: 'wx'});
      return '';
    }
    assert.equal(name, 'publication.exe');
    assert.equal(fs.existsSync(file), true);
    return '';
  };
  return {root, source, target, commands, run, options: {runnerTemp: root, attempt,
    systemRoot: path.join(root, 'Windows'), run}};
}

test('different successful bootstrap attempts publish identical strict tool bindings', t => {
  const publish = publisher();
  const f = fixture(t);
  const first = publish(f.options);
  assert.equal(fs.existsSync(f.source), false);
  assert.equal(first.path, path.join(f.target, 'bin'));
  assert.equal(first.environment.LLVM_CONFIG, path.join(f.target, 'bin', 'llvm-config.exe'));
  assert.equal(first.environment.CC, path.join(f.target, 'bin', 'clang.exe'));
  assert.equal(first.environment.CXX, path.join(f.target, 'bin', 'clang++.exe'));
  assert.equal(first.environment.CGO_ENABLED, '1');
  assert.equal(first.environment.GOFLAGS, '-tags=byollvm');
  assert.doesNotMatch(JSON.stringify(first), /plan9asm-msys2-attempt-/);
  fs.renameSync(f.target, path.join(f.root, 'retained-success-1'));
  fs.renameSync(path.join(f.root, 'plan9asm-llvm22-proof'), path.join(f.root, 'retained-proof-1'));
  const secondSource = path.join(f.root, 'plan9asm-msys2-attempt-2', 'msys64', 'clang64');
  fs.mkdirSync(path.dirname(secondSource), {recursive: true});
  fs.cpSync(path.join(f.root, 'retained-success-1'), secondSource, {recursive: true, errorOnExist: true});
  const failed = path.join(f.root, 'plan9asm-msys2-attempt-1', 'failed-update.txt');
  fs.writeFileSync(failed, 'preserved original bootstrap failure\n');
  const second = publish({...f.options, attempt: '2'});
  assert.deepEqual(second, first, 'strict compiler environments must not depend on which attempt succeeded');
  assert.equal(fs.readFileSync(failed, 'utf8'), 'preserved original bootstrap failure\n');
});

test('publication never covers an existing target or a redirected source', t => {
  const publish = publisher();
  for (const kind of ['file', 'directory', 'symlink', 'source-link', 'nested-link']) {
    const f = fixture(t);
    if (kind === 'file') fs.writeFileSync(f.target, 'keep target');
    if (kind === 'directory') fs.mkdirSync(f.target);
    if (kind === 'symlink') fs.symlinkSync(f.source, f.target, 'dir');
    if (kind === 'source-link') {
      const retained = path.join(f.root, 'original-source');
      fs.renameSync(f.source, retained);
      fs.symlinkSync(retained, f.source, 'dir');
    }
    if (kind === 'nested-link') fs.symlinkSync(path.join(f.source, 'include'), path.join(f.source, 'redirect'), 'dir');
    assert.throws(() => publish(f.options), undefined, kind);
    assert.equal(f.commands.filter(c => path.basename(c.file) === 'clang.exe').length, 0);
    assert.equal(fs.existsSync(f.source), true, 'refused publication cannot remove its source');
  }
});

test('unknown attempts, missing inputs and replacement during checks fail closed', t => {
  const publish = publisher();
  for (const attempt of ['', '0', '4', '01', '../1']) {
    const f = fixture(t);
    assert.throws(() => publish({...f.options, attempt}));
    assert.equal(fs.existsSync(f.target), false);
  }
  const missing = fixture(t);
  fs.unlinkSync(path.join(missing.source, 'bin', 'clang.exe'));
  assert.throws(() => publish(missing.options));
  const replaced = fixture(t);
  let changed = false;
  assert.throws(() => publish({...replaced.options, run(file, args, options) {
    if (!changed && path.basename(file) === 'powershell.exe') {
      changed = true;
      fs.renameSync(replaced.source, path.join(replaced.root, 'retained-replaced-source'));
      fs.mkdirSync(replaced.source);
    }
    return replaced.run(file, args, options);
  }}));
  assert.equal(fs.existsSync(replaced.target), false);
});

test('relocation, version, resource, compile and execution failures cannot publish bindings', t => {
  const publish = publisher();
  for (const kind of ['version', 'prefix', 'resources', 'flags', 'compile', 'execute', 'reparse']) {
    const f = fixture(t);
    assert.throws(() => publish({...f.options, run(file, args, options) {
      const name = path.basename(file), command = args.join(' ');
      if (kind === 'reparse' && name === 'powershell.exe') throw Error('native reparse point');
      if (kind === 'version' && name === 'llvm-config.exe' && command === '--version') return '23.0.0\n';
      if (kind === 'prefix' && command === '--prefix') return f.source + '\n';
      if (kind === 'resources' && command === '--print-resource-dir') return path.join(f.source, 'lib/clang/22') + '\n';
      if (kind === 'flags' && command === '--cflags') return '-I' + path.join(f.source, 'include') + '\n';
      if (kind === 'compile' && name === 'clang.exe' && args.includes('-o')) throw Error('compile/link failed');
      if (kind === 'execute' && name === 'publication.exe') throw Error('native execution failed');
      return f.run(file, args, options);
    }}), undefined, kind);
  }
});

test('the actual action installs first and publishes only through the stable native action', () => {
  const install = action.slice(action.indexOf('    - name: Install LLVM 22'));
  assert.match(install, /uses: \.\/\.github\/actions\/publish-windows-llvm22/);
  assert.doesNotMatch(install, />> "\$GITHUB_ENV"|>> "\$GITHUB_PATH"/);
  assert.match(install, /steps\.msys2_attempt_1\.outcome == 'success'.*'1'/);
  const metadata = fs.readFileSync('.github/actions/publish-windows-llvm22/action.yml', 'utf8');
  assert.match(metadata, /using: node24/);
  assert.doesNotMatch(metadata, /continue-on-error:|\n\s+if:/);
});
