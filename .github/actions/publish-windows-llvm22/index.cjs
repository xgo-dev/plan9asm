'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {execFileSync} = require('node:child_process');

function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}

function absent(file) {
  try { fs.lstatSync(file); } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  throw new Error('publication target already exists: ' + file);
}

function directory(file) {
  const stat = fs.lstatSync(file);
  requireThat(stat.isDirectory() && !stat.isSymbolicLink(), 'not an owned directory: ' + file);
  return stat;
}

function noLinks(file) {
  const stat = fs.lstatSync(file);
  requireThat(!stat.isSymbolicLink() && (stat.isFile() || stat.isDirectory()),
    'redirected or unsupported prefix entry: ' + file);
  if (stat.isDirectory()) {
    for (const name of fs.readdirSync(file)) noLinks(path.join(file, name));
  }
}

function publishPrefix({runnerTemp, attempt, systemRoot, run}) {
  requireThat(typeof attempt === 'string' && /^[123]$/.test(attempt), 'unknown successful bootstrap attempt');
  for (const value of [runnerTemp, systemRoot]) {
    requireThat(typeof value === 'string' && path.isAbsolute(value) &&
      path.normalize(value) === value && !/[\x00-\x1f]/.test(value), 'invalid absolute system path');
  }
  for (let ancestor = runnerTemp; ; ancestor = path.dirname(ancestor)) {
    directory(ancestor);
    if (ancestor === path.dirname(ancestor)) break;
  }
  const source = path.join(runnerTemp, 'plan9asm-msys2-attempt-' + attempt, 'msys64', 'clang64');
  const target = path.join(runnerTemp, 'plan9asm-llvm22');
  const proof = path.join(runnerTemp, 'plan9asm-llvm22-proof');
  directory(path.dirname(path.dirname(source)));
  directory(path.dirname(source));
  const original = directory(source);
  absent(target);
  absent(proof);
  noLinks(source);
  for (const relative of ['bin/llvm-config.exe', 'bin/clang.exe', 'bin/clang++.exe',
    'include/_mingw.h', 'lib/libkernel32.a']) {
    requireThat(fs.lstatSync(path.join(source, relative)).isFile(), 'missing prefix input: ' + relative);
  }

  // lstat covers symlinks/junctions; Windows attributes also reject other
  // reparse tags. Inspect before descending and never follow a redirected node.
  const checkReparse = `
$ErrorActionPreference = 'Stop'
$root = Get-Item -Force -LiteralPath $env:PLAN9ASM_LLVM22_CHECK
for ($item = $root; $null -ne $item; $item = $item.Parent) {
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse ancestor' }
}
$pending = [Collections.Generic.Stack[IO.FileSystemInfo]]::new()
$pending.Push($root)
while ($pending.Count) {
  $item = $pending.Pop()
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'reparse prefix entry' }
  if ($item -is [IO.DirectoryInfo]) {
    foreach ($child in $item.GetFileSystemInfos()) { $pending.Push($child) }
  }
}`;
  run(path.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', checkReparse],
    {env: {...process.env, PLAN9ASM_LLVM22_CHECK: source}});
  const checked = directory(source);
  requireThat(original.dev === checked.dev && original.ino === checked.ino, 'prefix replaced during validation');
  for (let ancestor = path.dirname(source); ; ancestor = path.dirname(ancestor)) {
    directory(ancestor);
    if (ancestor === path.dirname(ancestor)) break;
  }
  noLinks(source);
  absent(target);
  // Windows directory rename is same-volume and cannot replace an existing
  // file/directory. Do not copy, merge, remove failed attempts, or retry a move.
  fs.renameSync(source, target);
  const moved = directory(target);
  requireThat(original.dev === moved.dev && original.ino === moved.ino, 'published prefix identity changed');

  const bin = path.join(target, 'bin');
  // No bootstrap PATH: the relocation probe must resolve its DLLs, linker,
  // headers and runtime from the moved prefix, not a retained old installation.
  const env = {...process.env, PATH: [bin, path.join(systemRoot, 'System32'), systemRoot].join(path.delimiter)};
  if (process.platform === 'win32') {
    for (const name of Object.keys(env)) if (name.toUpperCase() === 'PATH' && name !== 'PATH') delete env[name];
  }
  const query = (file, args) => {
    const result = run(file, args, {env});
    requireThat(typeof result === 'string' && !result.includes('\0'), 'invalid tool output');
    return result;
  };
  const config = path.join(bin, 'llvm-config.exe');
  const clang = path.join(bin, 'clang.exe');
  const line = value => {
    requireThat(/^[^\r\n]+\r?\n?$/.test(value), 'expected one tool output line');
    return value.replace(/\r?\n$/, '');
  };
  const samePath = (value, expected) => path.normalize(line(value).replace(/[\\/]/g, path.sep)) === expected;
  requireThat(line(query(config, ['--version'])) === '22.1.8', 'expected LLVM 22.1.8');
  for (const [flag, relative] of [['--prefix', ''], ['--bindir', 'bin'], ['--includedir', 'include'], ['--libdir', 'lib']]) {
    requireThat(samePath(query(config, [flag]), path.join(target, relative)), 'LLVM prefix did not relocate: ' + flag);
  }
  requireThat(/^clang version 22\.1\.8(?:\s|$)/.test(query(clang, ['--version'])), 'expected Clang 22.1.8');
  const resources = path.join(target, 'lib', 'clang', '22');
  requireThat(samePath(query(clang, ['--print-resource-dir']), resources), 'Clang resources did not relocate');
  directory(resources);
  const flags = args => {
    const value = query(config, args).replace(/\r/g, '').replace(/\n/g, ' ').trim();
    requireThat(value.length > 0 && !/[\x00-\x1f]/.test(value) &&
      !/plan9asm-msys2-attempt-/i.test(value), 'invalid or attempt-dependent LLVM flags');
    return value;
  };
  const environment = {
    CGO_CFLAGS: flags(['--cflags']),
    CGO_CXXFLAGS: flags(['--cxxflags']),
    CGO_LDFLAGS: flags(['--ldflags', '--libs', 'all', '--system-libs']),
    LLVM_CONFIG: config, CC: clang, CXX: path.join(bin, 'clang++.exe'),
    CGO_ENABLED: '1', GOFLAGS: '-tags=byollvm',
  };
  fs.mkdirSync(proof); // Exclusive, retained on failure; never overwrite a probe.
  const input = path.join(proof, 'publication.c');
  const output = path.join(proof, 'publication.exe');
  fs.writeFileSync(input, '#include <stdint.h>\nint main(void) { return sizeof(uintptr_t) == 8 ? 0 : 1; }\n', {flag: 'wx'});
  query(clang, [input, '-o', output]);
  requireThat(fs.lstatSync(output).isFile(), 'compiler did not produce the native probe');
  query(output, []);
  return {environment, path: bin};
}

module.exports = {publishPrefix};
if (require.main === module) {
  try {
    requireThat(process.platform === 'win32', 'Windows LLVM publication requires Windows');
    const result = publishPrefix({runnerTemp: process.env.RUNNER_TEMP, attempt: process.env.INPUT_ATTEMPT,
      systemRoot: process.env.SystemRoot || process.env.SYSTEMROOT,
      run: (file, args, options) => execFileSync(file, args,
        {...options, encoding: 'utf8', timeout: 120000, maxBuffer: 1024 * 1024, windowsHide: true})});
    fs.appendFileSync(process.env.GITHUB_ENV, Object.entries(result.environment).map(([key, value]) => `${key}=${value}\n`).join(''));
    fs.appendFileSync(process.env.GITHUB_PATH, result.path + '\n');
    console.log('Published and executed LLVM 22.1.8 from ' + result.path);
  } catch (error) {
    console.error(error.stack || error.message);
    process.exitCode = 1;
  }
}
