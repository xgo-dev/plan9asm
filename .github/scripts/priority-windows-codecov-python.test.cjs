'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {jobBody} = require('./workflow-needs.cjs');

const source = fs.readFileSync(path.join(__dirname, '../workflows/windows-module.yml'), 'utf8');
const setup = `      - name: Set up compatible Python for coverage upload
        id: codecov_python
        uses: actions/setup-python@v7
        with:
          python-version: '3.13'
`;
const beforeUpload = `      - name: Check Codecov Python and pip ownership
        shell: bash
        env:
          CODECOV_PYTHON: \${{ steps.codecov_python.outputs.python-path }}
        run: |
          python - <<'PY'
          import os
          import shutil
          import subprocess
          import sys
          if sys.version_info[:2] != (3, 13):
              raise SystemExit("Codecov upload requires Python 3.13")
          if not os.path.samefile(sys.executable, os.environ["CODECOV_PYTHON"]):
              raise SystemExit("Codecov Python differs from setup-python output")
          pip = shutil.which("pip")
          expected = os.path.join(os.path.dirname(sys.executable), "Scripts", "pip.exe")
          if not pip or not os.path.samefile(pip, expected):
              raise SystemExit("Codecov pip is not owned by the selected Python")
          print("Codecov upload Python:", sys.version, sys.executable, flush=True)
          print("Codecov upload pip:", pip, flush=True)
          subprocess.run([pip, "--version"], check=True)
          PY
`;
const afterUpload = `      - name: Check installed Codecov CLI ownership
        shell: bash
        env:
          CODECOV_PYTHON: \${{ steps.codecov_python.outputs.python-path }}
        run: |
          python - <<'PY'
          import os
          import shutil
          import subprocess
          import sys
          if not os.path.samefile(sys.executable, os.environ["CODECOV_PYTHON"]):
              raise SystemExit("Codecov Python changed during upload")
          cli = shutil.which("codecovcli")
          expected = os.path.join(os.path.dirname(sys.executable), "Scripts", "codecovcli.exe")
          if not cli or not os.path.samefile(cli, expected):
              raise SystemExit("Codecov CLI is not owned by the selected Python")
          print("Codecov upload CLI:", cli, flush=True)
          subprocess.run([cli, "--help"], check=True)
          PY
`;

function oneStep(body, marker) {
  const found = body.split(/(?=^      - )/m).filter(step => step.includes(marker));
  assert.equal(found.length, 1, 'one actual step required: ' + marker);
  return found[0];
}

function requirePhaseBoundary(workflow) {
  for (const name of ['root-parts', 'other-owners']) {
    assert.doesNotMatch(jobBody(workflow, name), /setup-python|codecov-action|CODECOV_PYTHON/);
  }
  const body = jobBody(workflow, 'complete');
  const verify = body.indexOf('- name: Verify complete module and publish coverage\n');
  const retain = body.indexOf('- name: Retain independent completion evidence\n');
  const python = body.indexOf('uses: actions/setup-python@v7\n');
  const upload = body.indexOf('- name: Upload verified complete Windows module coverage\n');
  assert.ok(verify >= 0 && retain > verify && python > retain && upload > python,
    'the uploader must not alter Python/PATH before module qualification and evidence retention');
  assert.equal((body.match(/uses: actions\/setup-python@/g) || []).length, 1);
  const action = oneStep(body, '- name: Upload verified complete Windows module coverage\n');
  for (const input of ['use_pypi: true', 'use_oidc: true', 'disable_search: true',
    'fail_ci_if_error: true', 'files: ./coverage-windows-${{ inputs.module }}.out']) {
    assert.ok(action.includes(input), 'retain actual verified coverage upload input: ' + input);
  }
  assert.doesNotMatch(action, /continue-on-error:|if:|skip_validation:|PYO3_USE_ABI3_FORWARD_COMPATIBILITY/);
}

function requireCompatiblePython(workflow) {
  requirePhaseBoundary(workflow);
  const body = jobBody(workflow, 'complete');
  const python = oneStep(body, 'uses: actions/setup-python@v7\n');
  assert.match(python, /^        id: codecov_python$/m);
  assert.match(python, /^          python-version: '3\.13'$/m);
  assert.doesNotMatch(python, /python-version-file:|update-environment: false|allow-prereleases: true/);
}

function requireBindings(workflow) {
  const body = jobBody(workflow, 'complete');
  const before = oneStep(body, '- name: Check Codecov Python and pip ownership\n');
  const after = oneStep(body, '- name: Check installed Codecov CLI ownership\n');
  for (const step of [before, after]) {
    assert.match(step, /^        shell: bash$/m);
    assert.ok(step.includes('CODECOV_PYTHON: ${{ steps.codecov_python.outputs.python-path }}\n'));
    assert.ok(step.includes('os.path.samefile(sys.executable, os.environ["CODECOV_PYTHON"])'));
    assert.doesNotMatch(step, /continue-on-error:|if:|GITHUB_PATH|GITHUB_ENV|PYO3_USE_ABI3_FORWARD_COMPATIBILITY/);
  }
  for (const text of ['sys.version_info[:2] != (3, 13)', 'shutil.which("pip")',
    '"Scripts", "pip.exe"', 'not os.path.samefile(pip, expected)',
    'subprocess.run([pip, "--version"], check=True)']) {
    assert.ok(before.includes(text), 'the action executes PATH pip, not a python action input: ' + text);
  }
  for (const text of ['shutil.which("codecovcli")', '"Scripts", "codecovcli.exe"',
    'not os.path.samefile(cli, expected)', 'subprocess.run([cli, "--help"], check=True)']) {
    assert.ok(after.includes(text), 'the actual installed CLI must be observed: ' + text);
  }
  const upload = body.indexOf('- name: Upload verified complete Windows module coverage\n');
  assert.ok(body.indexOf(before) < upload && body.indexOf(after) > upload);
}

const fixture = source.replace(/      - uses: actions\/setup-python@v7\n        with:\n          python-version: '3\.x'\n/,
  setup + beforeUpload);
const completeFixture = fixture.endsWith(afterUpload) ? fixture : fixture + afterUpload;

test('Windows coverage uploader uses a compatible Python after qualification', () => requireCompatiblePython(source));
test('PATH pip and installed Codecov CLI are actually bound to the selected Python', () => requireBindings(source));
test('upload setup cannot change a live module toolbank or suppress an upload error', () => requirePhaseBoundary(source));

test('another Python minor or disabled PATH update cannot borrow the compatible pin', () => {
  requireCompatiblePython(completeFixture);
  requireBindings(completeFixture);
  for (const value of ['3.x', '3.15', '3.14', '${{ matrix.python }}']) {
    assert.throws(() => requireCompatiblePython(completeFixture.replace("python-version: '3.13'", `python-version: '${value}'`)));
  }
  assert.throws(() => requireCompatiblePython(completeFixture.replace("python-version: '3.13'", "python-version: '3.13'\n          update-environment: false")));
});

test('Python, pip and installed CLI binding checks cannot be omitted or softened', () => {
  for (const text of ['os.path.samefile(sys.executable, os.environ["CODECOV_PYTHON"])',
    'not os.path.samefile(pip, expected)', 'not os.path.samefile(cli, expected)',
    'subprocess.run([pip, "--version"], check=True)', 'subprocess.run([cli, "--help"], check=True)']) {
    assert.ok(completeFixture.includes(text));
    assert.throws(() => requireBindings(completeFixture.replace(text, 'REMOVED_CHECK')));
  }
});

test('compatible upload Python cannot move before module evidence is sealed', () => {
  const moved = completeFixture.replace(setup, '').replace('      - name: Verify complete module and publish coverage\n',
    setup + '      - name: Verify complete module and publish coverage\n');
  assert.throws(() => requirePhaseBoundary(moved));
});
