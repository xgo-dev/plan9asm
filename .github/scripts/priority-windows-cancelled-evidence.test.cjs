'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const source = fs.readFileSync(path.join(__dirname, '../workflows/windows-module.yml'), 'utf8');
const labels = ['Retain actual root evidence', 'Retain actual package evidence'];

function retention(source, label) {
  const start = source.indexOf('      - name: ' + label + '\n');
  assert.notEqual(start, -1, label);
  const tail = source.slice(start);
  const next = tail.search(/\n(?:      - |  [a-z-]+:)/);
  return tail.slice(0, next < 0 ? undefined : next);
}

function verify(source) {
  for (const label of labels) {
    const step = retention(source, label);
    assert.match(step, /^        if: \$\{\{ always\(\) \}\}$/m, label);
    assert.match(step, /uses: actions\/upload-artifact@v6/);
    assert.match(step, /if-no-files-found: error/);
  }
}

function condition(source, label, replacement) {
  const step = retention(source, label);
  const changed = step.replace(/^        if: .+\n/m, replacement);
  assert.notEqual(changed, step, label);
  return source.replace(step, changed);
}

// Mutations start from a complete positive fixture even while the real
// workflow is RED; missing or cancellation-dependent retention must fail.
let fixture = source;
for (const label of labels) {
  const step = retention(fixture, label);
  fixture = fixture.replace(step, step.replace(/^        if: .+$/m, '        if: ${{ always() }}'));
}

test('cancelled Windows owners retain diagnostic evidence, not successful coverage', () => {
  verify(source);
});

for (const label of labels) {
  test(label + ' cannot lose its cancellation-independent condition', () => {
    verify(fixture);
    assert.throws(() => verify(condition(fixture, label, '')));
  });
  test(label + ' cannot suppress reports after cancellation', () => {
    assert.throws(() => verify(condition(fixture, label, '        if: ${{ !cancelled() }}\n')));
  });
}
