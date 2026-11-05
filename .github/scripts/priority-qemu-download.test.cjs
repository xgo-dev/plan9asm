const assert = require('node:assert/strict');
const {execFileSync, spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const installer = fs.readFileSync('scripts/install-ci-qemu.sh', 'utf8');
const version = installer.match(/^version=(.+)$/m)[1];
const tools = ['qemu-aarch64', 'qemu-arm', 'qemu-i386'];

function quote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

async function downloadFixture(t, failures, corrupt = false) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'plan9asm-qemu-download-'));
  const payload = path.join(root, 'payload');
  const bin = path.join(root, 'bin');
  const destination = path.join(root, 'installed');
  fs.mkdirSync(payload);
  fs.mkdirSync(bin);
  t.after(() => fs.rmSync(root, {recursive: true, force: true}));

  for (const tool of tools) {
    fs.writeFileSync(path.join(payload, tool),
      `#!/bin/sh\nprintf '%s\\n' '${tool} version ${version} fixture'\n`,
      {mode: 0o755});
  }
  const archive = path.join(root, 'qemu.tar.gz');
  execFileSync('tar', ['-czf', archive, '-C', payload, ...tools]);
  const bytes = fs.readFileSync(archive);
  const checksum = createHash('sha256').update(bytes).digest('hex');

  // Exercise the real curl retry state machine, without contacting GitHub or
  // downloading emulator binaries. Only the test copy uses this local archive.
  let requests = 0;
  const server = http.createServer((_request, response) => {
    requests++;
    if (requests <= failures) {
      response.writeHead(504);
      response.end('temporary release gateway failure');
    } else {
      response.writeHead(200);
      response.end(corrupt ? Buffer.from('corrupt archive') : bytes);
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const endpoint = `http://127.0.0.1:${server.address().port}/qemu.tar.gz`;
  const originalURL = 'https://github.com/tonistiigi/binfmt/releases/download/' +
    '$release/qemu_v${version}_linux-amd64.tar.gz';
  assert.ok(installer.includes(originalURL));
  const script = installer.replace(originalURL, endpoint)
    .replace(/^checksum=[a-f0-9]{64}$/m, `checksum=${checksum}`);
  fs.writeFileSync(path.join(root, 'install.sh'), script);
  fs.writeFileSync(path.join(bin, 'uname'),
    '#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo x86_64;; *) exit 1;; esac\n',
    {mode: 0o755});
  if (process.platform === 'darwin') {
    // The fixture runs the Linux installer; Darwin's BSD sha256sum does not
    // accept its GNU long options. shasum performs the same real hash check.
    const shasum = execFileSync('which', ['shasum'], {encoding: 'utf8'}).trim();
    fs.writeFileSync(path.join(bin, 'sha256sum'),
      `#!/bin/sh\nexec ${quote(shasum)} -a 256 "$@"\n`, {mode: 0o755});
  }

  // A bad checksum must stop before extraction, not merely fail in tar later.
  const realTar = execFileSync('which', ['tar'], {encoding: 'utf8'}).trim();
  const extracted = path.join(root, 'extracted');
  fs.writeFileSync(path.join(bin, 'tar'),
    `#!/bin/sh\n: > ${quote(extracted)}\nexec ${quote(realTar)} "$@"\n`,
    {mode: 0o755});
  const child = spawn('bash', [path.join(root, 'install.sh'), destination], {
    env: {...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}`,
      NO_PROXY: '127.0.0.1', GITHUB_PATH: path.join(root, 'github-path')},
    timeout: 40000,
  });
  let stderr = '';
  child.stderr.on('data', data => { stderr += data; });
  child.stdout.resume();
  const code = await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('close', (status, signal) => {
      assert.equal(signal, null, stderr);
      resolve(status);
    });
  });
  return {code, requests, stderr, destination, extracted};
}

test('pinned QEMU download survives three consecutive release gateway errors',
  {timeout: 45000}, async t => {
    const result = await downloadFixture(t, 3);
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.requests, 4);
    for (const tool of tools) {
      assert.ok(fs.existsSync(path.join(result.destination, tool)));
    }
  });

test('persistent QEMU download errors remain bounded and fatal',
  {timeout: 45000}, async t => {
    const result = await downloadFixture(t, Infinity);
    assert.notEqual(result.code, 0);
    assert.ok(result.requests <= 6, `unbounded requests: ${result.requests}`);
    assert.ok(!fs.existsSync(result.extracted));
    for (const tool of tools) {
      assert.ok(!fs.existsSync(path.join(result.destination, tool)));
    }
  });

test('a downloaded QEMU archive still requires its exact checksum',
  {timeout: 45000}, async t => {
    const result = await downloadFixture(t, 0, true);
    assert.notEqual(result.code, 0);
    assert.equal(result.requests, 1);
    assert.ok(!fs.existsSync(result.extracted));
  });
