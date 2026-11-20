const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');

const action = fs.readFileSync('.github/actions/setup-windows-llvm22/action.yml', 'utf8');

function bootstrapSteps() {
  const bootstrap = action.slice(action.indexOf('  steps:'), action.indexOf('    - name: Install LLVM 22'));
  return bootstrap.split(/(?=    - name:)/).filter(step => step.includes('uses: msys2/setup-msys2@v2'));
}

// Model the observed setup-msys2 implementation at ec48f7c5447b3140e2b088413ae3a55687bccb6e:
// release installs into join(location || RUNNER_TEMP, 'msys64'), refuses an
// existing directory, and writes the msys2 shell before updating packages.
// A failed download/extraction/update can therefore leave the directory behind.
function bootstrap(updateOutcomes) {
  const runnerTemp = 'D:\\runner temp';
  const directories = new Set();
  const attempts = [];
  let shellInstallation;
  for (const [index, step] of bootstrapSteps().entries()) {
    if (index > 0) {
      const condition = step.match(/if: \$\{\{ (.+) \}\}/)?.[1];
      const expected = Array.from({ length: index }, (_, prior) =>
        `steps.msys2_attempt_${prior + 1}.outcome == 'failure'`).join(' && ');
      assert.equal(condition, expected, 'retry only after every prior failure');
      if (!attempts.every(attempt => attempt.outcome === 'failure')) break;
    }
    const location = step.match(/\n        location: (.+)/)?.[1]
      .replace('${{ runner.temp }}', runnerTemp) || runnerTemp;
    const installation = path.win32.join(location, 'msys64');
    const collision = directories.has(installation);
    let outcome = 'failure';
    if (!collision) {
      directories.add(installation);
      shellInstallation = installation;
      outcome = updateOutcomes[index] === 0 ? 'success' : 'failure';
    }
    attempts.push({ installation, collision, outcome });
    if (outcome === 'success') break;
    if (!/continue-on-error: true/.test(step)) {
      return { attempts, directories, shellInstallation, installerMayRun: false };
    }
  }
  return {
    attempts, directories, shellInstallation,
    installerMayRun: attempts.at(-1)?.outcome === 'success',
  };
}

test('MSYS2 bootstrap retries are bounded and the final failure remains fatal', () => {
  const attempts = bootstrapSteps();
  assert.equal(attempts.length, 3);
  for (const [index, step] of attempts.entries()) {
    assert.match(step, new RegExp(`id: msys2_attempt_${index + 1}`));
    assert.match(step, /msystem: CLANG64/);
    assert.match(step, /path-type: inherit/);
    assert.match(step, /update: true/);
    if (index < 2) {
      assert.match(step, /continue-on-error: true/);
    } else {
      assert.doesNotMatch(step, /continue-on-error:/);
    }
    if (index > 0) {
      for (let prior = 1; prior <= index; prior++) {
        assert.match(step, new RegExp(`steps\\.msys2_attempt_${prior}\\.outcome == 'failure'`));
      }
    }
  }
});

test('a partially installed MSYS2 directory cannot poison subsequent bootstrap attempts', () => {
  for (const outcomes of [[1, 0], [1, 1, 0]]) {
    const result = bootstrap(outcomes);
    assert.equal(result.installerMayRun, true, 'a later successful update must reach LLVM installation');
    assert.equal(result.attempts.length, outcomes.length);
    assert.ok(result.attempts.every(attempt => !attempt.collision), 'each retry must start a fresh installation');
    assert.equal(result.directories.size, outcomes.length, 'failed bootstrap directories are retained, not deleted');
    assert.equal(result.shellInstallation, result.attempts.at(-1).installation,
      'the official msys2 wrapper must select the successful attempt, not the first failed installation');
  }
});

test('all three bootstrap attempts explicitly own distinct fresh runner-temp locations', () => {
  const locations = bootstrapSteps().map((step, index) => {
    assert.match(step, /\n        release: true\n/);
    const location = step.match(/\n        location: (.+)/)?.[1];
    assert.equal(location, `\${{ runner.temp }}/plan9asm-msys2-attempt-${index + 1}`);
    return location;
  });
  assert.equal(new Set(locations).size, 3);
  assert.doesNotMatch(action, /release: false|Remove-Item|rm\s+-[rf]|SigLevel\s*=|--nosignature|--skippgpcheck/);
});

test('bootstrap success short-circuits retries and exhausted bootstrap remains fatal', () => {
  const first = bootstrap([0]);
  assert.equal(first.attempts.length, 1);
  assert.equal(first.installerMayRun, true);
  assert.equal(first.shellInstallation, first.attempts[0].installation);
  const exhausted = bootstrap([1, 1, 1]);
  assert.equal(exhausted.attempts.length, 3);
  assert.ok(exhausted.attempts.every(attempt => !attempt.collision));
  assert.equal(exhausted.installerMayRun, false, 'no LLVM transaction or build environment after final failure');
});

function install(outcomes, version = '22.1.8') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'plan9asm-llvm-install-'));
  try {
    const installStep = action.slice(action.indexOf('    - name: Install LLVM 22')).split(/\n    - name:/)[0];
    const run = installStep.slice(installStep.indexOf('      run: |\n') + '      run: |\n'.length)
      .split('\n').map(line => line.startsWith('        ') ? line.slice(8) : line).join('\n');
    const script = `
mock_pacman_calls=0
outcomes=(${outcomes.join(' ')})
pacman() {
  mock_pacman_calls=$((mock_pacman_calls + 1))
  printf 'PACMAN:'
  printf ' %s' "$@"
  printf '\\n'
  return "\${outcomes[mock_pacman_calls - 1]}"
}
sleep() { test "$1" = 5; printf 'RETRY_WAIT\\n'; }
llvm-config() {
  if [[ "$1" == --version ]]; then printf '%s\\n' "$MOCK_LLVM_VERSION";
  else printf 'checked-flags\\n'; fi
}
cygpath() { printf 'checked-clang64-bin\\n'; }
${run}`;
    const result = spawnSync('bash', ['-c', script], {
      encoding: 'utf8', timeout: 5000,
      env: {
        ...process.env,
        LLVM_VERSION: '22.1.8', LLVM_PACKAGE_VERSION: '22.1.8-2',
        LLVM_RUNTIME_PACKAGE_VERSION: '22.1.8-1', MOCK_LLVM_VERSION: version,
        GITHUB_ENV: path.join(directory, 'environment'), GITHUB_PATH: path.join(directory, 'path'),
      },
    });
    assert.ifError(result.error);
    return {
      ...result,
      environment: fs.existsSync(path.join(directory, 'environment'))
        ? fs.readFileSync(path.join(directory, 'environment'), 'utf8') : '',
    };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test('actual installer script retries the identical pinned transaction only', () => {
  for (const outcomes of [[0], [67, 0], [67, 68, 0]]) {
    const result = install(outcomes);
    assert.equal(result.status, 0, result.stderr);
    const transactions = result.stdout.split('\n').filter(line => line.startsWith('PACMAN:'));
    assert.equal(transactions.length, outcomes.length);
    assert.equal(new Set(transactions).size, 1);
    assert.match(transactions[0], /llvm-22\.1\.8-2-any\.pkg\.tar\.zst/);
    assert.doesNotMatch(transactions[0], /llvm-23/);
    assert.equal((result.stdout.match(/RETRY_WAIT/g) || []).length, outcomes.length - 1);
    assert.equal(result.environment, '', 'installation alone cannot publish attempt-dependent bindings');
  }
});

test('exhausted installation and wrong LLVM version publish no build environment', () => {
  const exhausted = install([67, 68, 69]);
  assert.equal(exhausted.status, 69, exhausted.stderr);
  assert.equal((exhausted.stdout.match(/PACMAN:/g) || []).length, 3);
  assert.equal(exhausted.environment, '');
  const wrongVersion = install([0], '23.0.0');
  assert.equal(wrongVersion.status, 1);
  assert.match(wrongVersion.stderr, /expected LLVM 22\.1\.8, got 23\.0\.0/);
  assert.equal(wrongVersion.environment, '');
});
