'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const test = require('node:test');

// These executable protocol fixtures never invoke Go or LLVM. The real Python
// validator and actual checked-out shell script still decide scan failures.
const goFixture = [
  '#!/usr/bin/env bash', 'set -euo pipefail',
  'if [[ "$1" == env ]]; then printenv "$2"; exit; fi',
  'if [[ "$1" == version ]]; then printf "protocol Go version only\\n"; exit; fi',
  '[[ "$1" == build ]] || exit 91',
  'while (( $# > 0 )); do',
  '  if [[ "$1" == -o ]]; then',
  '    case "$2" in',
  '      *plan9asmscan|*plan9asmscan.exe) role=scanner; source=$CORPUS_PROTOCOL_SCANNER ;;',
  '      *) role=cli; source=$CORPUS_PROTOCOL_TRANSLATOR ;;',
  '    esac',
  '    printf "build|%s\\n" "$role" >> "$CORPUS_PROTOCOL_TRACE"',
  '    [[ "$CORPUS_PROTOCOL_MODE" != "build-$role" ]] || exit 42',
  '    cp "$source" "$2"', '    exit', '  fi', '  shift', 'done', 'exit 92',
].join('\n') + '\n';

const scannerFixture = [
  '#!/usr/bin/env bash', 'set -euo pipefail', 'goos= goarch= output=',
  'while (( $# > 0 )); do', '  IFS== read -r key value <<< "$1"',
  '  case "$key" in',
  '    -goos) goos=$value ;; -goarch) goarch=$value ;;',
  '    -out) shift; output=$1 ;;', '  esac', '  shift', 'done',
  'printf "scan|%s/%s|%s|%s|%s|%s|%s\\n" "$goos" "$goarch" "$GO386" "$GOAMD64" "$GOARM" "$GOARM64" "$GOWASM" >> "$CORPUS_PROTOCOL_TRACE"',
  '[[ "$CORPUS_PROTOCOL_MODE" != scanner-exit ]] || { echo protocol-scanner-failure >&2; exit 43; }',
  'if [[ "$CORPUS_PROTOCOL_MODE" == malformed ]]; then printf "{broken\\n" > "$output"; exit; fi',
  "unsupported='[]'; forms='[]'; errors='[]'",
  'case "$CORPUS_PROTOCOL_MODE" in',
  "  op) unsupported='[{\"op\":\"PROTOCOL_BAD\",\"count\":1}]' ;;",
  "  form) forms='[{\"form\":\"PROTOCOL_BAD register\",\"errors\":[\"protocol form rejection\"]}]' ;;",
  "  parse) errors='[{\"File\":\"protocol.s\",\"Err\":\"protocol parse rejection\"}]' ;;",
  'esac',
  'printf \'{"std_pkgs_with_sfile":1,"asm_files":1,"unsupported":%s,"unsupported_by_form":%s,"parse_errs":%s}\\n\' "$unsupported" "$forms" "$errors" > "$output"',
].join('\n') + '\n';

const translatorFixture = [
  '#!/usr/bin/env bash', 'set -euo pipefail',
  '[[ "$1" == transpile && "$GOTOOLCHAIN" == local ]] || exit 93', 'shift',
  'goos= goarch= output= meta=',
  'while (( $# > 0 )); do',
  '  IFS== read -r key value <<< "$1"',
  '  case "$key" in',
  '    -goos) goos=$value ;; -goarch) goarch=$value ;;',
  '    -dir) shift; output=$1 ;; -meta) shift; meta=$1 ;;',
  '    std) ;; *) exit 94 ;;', '  esac', '  shift', 'done',
  'printf "transpile|%s/%s|%s|%s|%s|%s|%s\\n" "$goos" "$goarch" "$GO386" "$GOAMD64" "$GOARM" "$GOARM64" "$GOWASM" >> "$CORPUS_PROTOCOL_TRACE"',
  '[[ "$CORPUS_PROTOCOL_MODE" != transpile ]] || { echo protocol-transpile-failure >&2; exit 44; }',
  'mkdir -p "$output"',
  '[[ "$CORPUS_PROTOCOL_MODE" != empty ]] || exit 0',
  'printf "; protocol fixture, not LLVM compilation evidence\\n" > "$output/protocol.ll"',
  'if [[ "$goarch" == wasm ]]; then printf "; second protocol input, not LLVM evidence\\n" > "$output/second.ll"; fi',
  'printf "{}\\n" > "$meta"',
].join('\n') + '\n';

const llvmFixture = [
  '#!/usr/bin/env bash', 'set -euo pipefail',
  'if [[ "$1" == --version ]]; then printf "LLVM version 22.1.8\\n"; exit; fi',
  'triple= output= input= object=false',
  'while (( $# > 0 )); do', '  IFS== read -r key value <<< "$1"',
  '  case "$key" in',
  '    -mtriple) triple=$value ;; -filetype) [[ "$value" == obj ]] || exit 95; object=true ;;',
  '    -o) shift; output=$1 ;; *.ll) input=$1 ;;', '  esac', '  shift', 'done',
  '[[ "$object" == true && -n "$triple" && -n "$output" && -f "$input" ]] || exit 96',
  'name=$(basename "$input")',
  'printf "object|%s|%s\\n" "$triple" "$name" >> "$CORPUS_PROTOCOL_TRACE"',
  '[[ "$CORPUS_PROTOCOL_MODE" != object ]] || { echo protocol-object-failure >&2; exit 45; }',
  'if [[ "$CORPUS_PROTOCOL_MODE" == second-object && "$name" == second.ll ]]; then echo protocol-second-object-failure >&2; exit 47; fi',
  'printf "protocol fixture only, not a real object\\n" > "$output"',
].join('\n') + '\n';

const llvmConfigFixture = [
  '#!/usr/bin/env bash', 'set -euo pipefail',
  'case "$1" in',
  '  --version) if [[ "$CORPUS_PROTOCOL_MODE" == wrong-llvm ]]; then echo 23.0.0; else echo 22.1.8; fi ;;',
  '  --bindir) if [[ "$CORPUS_PROTOCOL_MODE" == missing-llvm ]]; then echo "$CORPUS_PROTOCOL_BIN/missing"; else echo "$CORPUS_PROTOCOL_BIN"; fi ;;',
  '  *) exit 97 ;;', 'esac',
].join('\n') + '\n';

function observeNativeBashExecutable() {
  const command = process.platform === 'win32'
    ? 'if [[ "$BASH" == *.exe ]]; then cygpath -w -- "$BASH"; else cygpath -w -- "$BASH.exe"; fi'
    : 'printf "%s\\n" "$BASH"';
  // Resolve only in the original native environment. Windows Node cannot
  // resolve a command name through a child's colon-delimited MSYS PATH.
  const result = spawnSync('bash', ['-c', command], {env: process.env,
    encoding: 'utf8', timeout: 5000});
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, '');
  const line = result.stdout.match(/^([^\r\n\0]+)\r?\n$/);
  assert.ok(line, 'one complete native Bash executable path');
  const executable = line[1];
  assert.equal(executable, executable.trim(), 'an unpadded executable path');
  assert.ok(path.isAbsolute(executable), 'native absolute Bash executable');
  assert.ok(fs.statSync(executable).isFile(), 'Bash executable must be a regular file');
  fs.accessSync(executable, fs.constants.X_OK);
  return executable;
}

const bashExecutable = observeNativeBashExecutable();

function runCorpusShell(args, options) {
  return spawnSync(bashExecutable, args, options);
}

function shellPaths(names) {
  if (process.platform !== 'win32') return names;
  const result = runCorpusShell(['-c',
    'for name in "$@"; do cygpath -u -- "$name" || exit; done', 'corpus-paths', ...names],
  {encoding: 'utf8', timeout: 5000});
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  const converted = result.stdout.trimEnd().split(/\r?\n/);
  assert.equal(converted.length, names.length);
  return converted;
}

function fixture(t, mode = 'success', targets = '') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'stdlib-corpus-protocol-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const bin = path.join(directory, 'bin');
  const scripts = path.join(directory, 'scripts');
  fs.mkdirSync(bin);
  fs.mkdirSync(scripts);
  for (const name of ['check-stdlib-corpus.sh', 'llvm22.sh']) {
    fs.copyFileSync(path.join(__dirname, '../../scripts', name), path.join(scripts, name));
  }
  for (const [name, source] of Object.entries({go: goFixture, scanner: scannerFixture,
    translator: translatorFixture, llc: llvmFixture, 'llvm-config': llvmConfigFixture})) {
    fs.writeFileSync(path.join(bin, name), source, {mode: 0o700});
  }
  if (mode === 'broken-python') {
    for (const name of ['python', 'python3']) {
      fs.writeFileSync(path.join(bin, name), '#!/usr/bin/env bash\necho protocol-python-failure >&2\nexit 46\n', {mode: 0o700});
    }
  }
  const trace = path.join(directory, 'trace');
  const [shellBin, shellScript, scanner, translator, shellTrace, config] = shellPaths([
    bin, path.join(scripts, 'check-stdlib-corpus.sh'), path.join(bin, 'scanner'),
    path.join(bin, 'translator'), trace, path.join(bin, 'llvm-config'),
  ]);
  const shellPath = runCorpusShell(['-c', 'printf "%s" "$PATH"'],
    {encoding: 'utf8', timeout: 5000});
  assert.ifError(shellPath.error);
  assert.equal(shellPath.status, 0, shellPath.stderr);
  const environment = {...process.env,
    PATH: shellBin + ':' + shellPath.stdout, LLVM_CONFIG: config,
    PLAN9ASM_CMD: mode === 'missing-cli' ? shellBin + '/absent' : '',
    PLAN9ASM_CORPUS_TARGETS: targets, PLAN9ASM_CORPUS_INCLUDE_WINDOWS: '1',
    CORPUS_PROTOCOL_BIN: shellBin, CORPUS_PROTOCOL_SCANNER: scanner,
    CORPUS_PROTOCOL_TRANSLATOR: translator, CORPUS_PROTOCOL_TRACE: shellTrace,
    CORPUS_PROTOCOL_MODE: mode,
  };
  return {
    run(args = []) {
      const result = runCorpusShell([shellScript, ...args], {cwd: directory,
        env: environment, encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024});
      assert.ifError(result.error);
      assert.equal(result.signal, null, result.stderr);
      assert.equal(typeof result.status, 'number');
      const rows = fs.existsSync(trace) ? fs.readFileSync(trace, 'utf8').trimEnd().split('\n') : [];
      return {...result, rows, output: result.stdout + result.stderr};
    },
  };
}

test('corpus Bash transport uses the observed executable even when child PATH has no Bash', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'corpus-shell-transport-'));
  t.after(() => fs.rmSync(directory, {recursive: true, force: true}));
  const command = process.platform === 'win32'
    ? 'if [[ "$BASH" == *.exe ]]; then cygpath -w -- "$BASH"; else cygpath -w -- "$BASH.exe"; fi'
    : 'printf "%s\\n" "$BASH"';
  // Independent prior uses the original native PATH, never the child's POSIX
  // search list. This is process transport, not a compiler/native-ISA oracle.
  const observed = spawnSync('bash', ['-c', command], {env: process.env,
    encoding: 'utf8', timeout: 5000});
  assert.ifError(observed.error);
  assert.equal(observed.status, 0, observed.stderr);
  const executable = observed.stdout.replace(/\r?\n$/, '');
  assert.ok(path.isAbsolute(executable));
  assert.doesNotMatch(executable, /[\r\n\0]/);
  assert.ok(fs.statSync(executable).isFile());
  fs.accessSync(executable, fs.constants.X_OK);

  const options = {env: {...process.env, PATH: directory}, encoding: 'utf8', timeout: 5000};
  const args = ['-c', 'printf "CORPUS_SHELL_TRANSPORT_PASS\\n"'];
  const named = spawnSync('bash', args, options);
  assert.equal(named.error && named.error.code, 'ENOENT', 'negative must fail actual command lookup');
  const absolute = spawnSync(executable, args, options);
  assert.ifError(absolute.error);
  assert.equal(absolute.status, 0, absolute.stderr);
  assert.equal(absolute.stdout, 'CORPUS_SHELL_TRANSPORT_PASS\n');

  const actual = runCorpusShell(args, options);
  assert.ifError(actual.error);
  assert.equal(actual.status, 0, actual.stderr);
  assert.equal(actual.stdout, absolute.stdout);
});

test('corpus rewritten-PATH consumers never resolve Bash by name', () => {
  for (const consumer of [runCorpusShell, shellPaths, fixture]) {
    assert.doesNotMatch(consumer.toString(), /spawnSync\(['"]bash['"]/,
      consumer.name + ': only the original native-environment bootstrap may use a name');
  }
});

function expectedScans() {
  const rows = [];
  const add = (target, role = '', value = '') => {
    const settings = ['GO386', 'GOAMD64', 'GOARM', 'GOARM64', 'GOWASM'].map(name =>
      name === role ? value : '');
    rows.push(['scan', target, ...settings].join('|'));
  };
  for (const value of ['sse2', 'softfloat']) add('linux/386', 'GO386', value);
  for (const value of ['v1', 'v2', 'v3', 'v4']) add('linux/amd64', 'GOAMD64', value);
  for (const value of ['5', '5,hardfloat', '6', '6,softfloat', '7', '7,softfloat']) add('linux/arm', 'GOARM', value);
  for (let index = 0; index < 10; index++) add('linux/arm64', 'GOARM64', 'v8.' + index);
  for (let index = 0; index < 6; index++) add('linux/arm64', 'GOARM64', 'v9.' + index);
  for (const value of ['v8.0,lse', 'v8.0,crypto', 'v8.0,lse,crypto']) add('linux/arm64', 'GOARM64', value);
  add('darwin/amd64');
  add('darwin/arm64');
  for (const target of ['js/wasm', 'wasip1/wasm']) {
    add(target);
    for (const value of ['satconv', 'signext', 'satconv,signext']) add(target, 'GOWASM', value);
  }
  for (const target of ['windows/386', 'windows/amd64', 'windows/arm64']) add(target);
  assert.equal(rows.length, 44, 'all original default profiles');
  assert.equal(new Set(rows).size, 44, 'each original profile exactly once');
  return rows;
}

function wasmScanRows() {
  const rows = expectedScans().filter(row => /^scan\|(?:js|wasip1)\/wasm\|/.test(row));
  assert.equal(rows.length, 8, 'complete JS/WASI plus all GOWASM profiles');
  return rows;
}

function wasmObjectRows(scan) {
  const triple = scan.split('|')[1] === 'js/wasm' ? 'wasm32-unknown-unknown' : 'wasm32-unknown-wasi';
  return ['protocol.ll', 'second.ll'].map(name => 'object|' + triple + '|' + name);
}

test('instruction-only corpus scans all 44 profiles and compiles every full contextual WASM source', t => {
  const result = fixture(t).run(['--instructions-only']);
  assert.equal(result.status, 0, result.output);
  assert.deepEqual(result.rows.filter(row => row.startsWith('scan|')), expectedScans());
  const wasm = new Set(wasmScanRows());
  const expected = ['build|scanner', 'build|cli'];
  for (const scan of expectedScans()) {
    expected.push(scan);
    if (wasm.has(scan)) expected.push(scan.replace('scan|', 'transpile|'), ...wasmObjectRows(scan));
  }
  assert.deepEqual(result.rows, expected,
    'WASM needs whole typed-stack source and every LLVM object; other architectures remain scan-only');
});

test('default corpus retains all 44 whole-source and object compilation protocols', t => {
  const result = fixture(t).run();
  assert.equal(result.status, 0, result.output);
  assert.deepEqual(result.rows.filter(row => row.startsWith('scan|')), expectedScans());
  const translations = result.rows.filter(row => row.startsWith('transpile|'));
  assert.deepEqual(translations, expectedScans().map(row => row.replace('scan|', 'transpile|')));
  assert.equal(result.rows.filter(row => row.startsWith('object|')).length, 52,
    'all 44 targets plus the second generated file in each of eight WASM profiles');
});

test('both corpus modes keep scan and required-tool failures fatal', async t => {
  const failures = {
    op: /unsupported ops remain: PROTOCOL_BAD/,
    form: /unsupported operand forms remain: PROTOCOL_BAD/,
    parse: /parse errors remain: protocol.s: protocol parse rejection/,
    malformed: /JSONDecodeError/,
    'scanner-exit': /protocol-scanner-failure/,
    'build-scanner': /build/,
    'build-cli': /build/,
    'wrong-llvm': /LLVM_CONFIG must select LLVM 22/,
    'missing-llvm': /LLVM 22 llc not found/,
    'missing-cli': /PLAN9ASM_CMD is not executable/,
    'broken-python': /protocol-python-failure/,
  };
  for (const args of [[], ['--instructions-only']]) {
    for (const [mode, diagnostic] of Object.entries(failures)) {
      await t.test((args.length ? 'instructions/' : 'default/') + mode, t => {
        const result = fixture(t, mode, 'windows/arm64').run(args);
        assert.notEqual(result.status, 0, result.output);
        if (mode.startsWith('build-')) {
          assert.ok(result.rows.includes('build|' + mode.slice('build-'.length)), 'actual failed tool build');
        } else {
          assert.match(result.output, diagnostic);
        }
      });
    }
  }
});

test('instruction-only mode never starts a failing whole-runtime transpiler', t => {
  const result = fixture(t, 'transpile', 'windows/arm64').run(['--instructions-only']);
  assert.equal(result.status, 0, result.output);
  assert.deepEqual(result.rows.filter(row => row.startsWith('scan|')), ['scan|windows/arm64|||||']);
  assert.deepEqual(result.rows.filter(row => /^(transpile|object)\|/.test(row)), []);
});

test('instruction-only mode cannot hide any contextual WASM source or object failure', async t => {
  for (const scan of wasmScanRows()) {
    const fields = scan.split('|');
    const target = fields[1] + (fields[6] ? '/' + fields[6].replaceAll(',', '+') : '');
    for (const mode of ['transpile', 'empty', 'object', 'second-object']) {
      await t.test(target + '/' + mode, t => {
        const result = fixture(t, mode, target).run(['--instructions-only']);
        assert.notEqual(result.status, 0, 'WASM Context was accepted without its complete source/object companion');
        assert.match(result.output, mode === 'empty' ? /no \.ll files generated/ :
          new RegExp('protocol-' + mode + '-failure'));
        assert.deepEqual(result.rows.filter(row => row.startsWith('scan|')), [scan]);
        assert.deepEqual(result.rows.filter(row => row.startsWith('transpile|')),
          [scan.replace('scan|', 'transpile|')]);
        if (mode === 'second-object') {
          assert.deepEqual(result.rows.filter(row => row.startsWith('object|')), wasmObjectRows(scan));
        }
      });
    }
  }
});

test('default corpus retains transpile, empty-output and object failures', async t => {
  for (const mode of ['transpile', 'empty', 'object']) {
    await t.test(mode, t => {
      const result = fixture(t, mode, 'windows/arm64').run();
      assert.notEqual(result.status, 0, result.output);
      assert.match(result.output, mode === 'empty' ? /no \.ll files generated/ :
        new RegExp('protocol-' + mode + '-failure'));
    });
  }
});

test('corpus mode arguments reject unknown, duplicate and extra operands', async t => {
  for (const args of [['--unknown'], ['--instructions-only', '--instructions-only'],
    ['--instructions-only', 'std'], ['--instructions-only=true'], ['std']]) {
    await t.test(args.join(' '), t => {
      const result = fixture(t, 'success', 'windows/arm64').run(args);
      assert.notEqual(result.status, 0, 'unrecognized mode silently ran the default protocol');
      assert.deepEqual(result.rows, [], 'invalid arguments must fail before any tool invocation');
    });
  }
});
