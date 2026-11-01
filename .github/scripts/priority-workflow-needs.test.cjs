'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('node:fs');
const {jobBody, jobNeeds, requireJobNeeds} = require('./workflow-needs.cjs');

function replaceNeeds(source, name, declaration) {
  const body = jobBody(source, name);
  const changed = body.replace(/^    needs:.*$/m, '    needs: ' + declaration);
  assert.notEqual(body, changed, 'negative/format control must change its actual job');
  return source.replace(body, changed);
}

test('concrete dependencies reject duplicates, expressions, self references and absent jobs', () => {
  const source = 'jobs:\n  first:\n    runs-on: ubuntu-latest\n' +
    '  second:\n    runs-on: ubuntu-latest\n' +
    '  complete:\n    needs: [first, second]\n';
  const requireComplete = value => requireJobNeeds(value, 'complete', ['first', 'second']);
  assert.deepEqual(requireComplete(source), ['first', 'second']);
  assert.deepEqual(requireComplete(replaceNeeds(source, 'complete', '["second", "first"]')), ['second', 'first']);
  for (const declaration of [
    '[first, first]', '[first, absent]', '[first, complete]',
    '${{ needs.from_another_job }}', '[]', '[first,]', '[first]', '[second]',
  ]) assert.throws(() => requireComplete(replaceNeeds(source, 'complete', declaration)));
  const body = jobBody(source, 'complete');
  assert.throws(() => requireComplete(source.replace(body,
    body.replace(/^    needs:.*$/m, '    needs: first\n    needs: second'))));
  assert.throws(() => requireComplete(source.replace(body, body.replace(/^    needs:.*\n/m, ''))));
  assert.throws(() => requireComplete(source + '\n  complete:\n'));
  assert.throws(() => requireComplete(source.replace('\n  first:\n', '\n  absent:\n')));
});

test('main and reusable CLI completion retain every actual owner gate', () => {
  for (const [file, name, required] of [
    ['go-ci.yml', 'module-completion', ['test', 'nested-cli', 'race', 'coverage', 'nested-cli-coverage']],
    ['windows-module.yml', 'complete', ['root-parts', 'other-owners']],
    ['linux-cli-module.yml', 'complete', ['root-parts']],
  ]) {
    const source = fs.readFileSync('.github/workflows/' + file, 'utf8');
    requireJobNeeds(source, name, required);
    requireJobNeeds(replaceNeeds(source, name, '[' + required.slice().reverse().join(', ') + ']'), name, required);
    for (const missing of required) {
      const reduced = '[' + required.filter(gate => gate !== missing).join(', ') + ']';
      assert.throws(() => requireJobNeeds(replaceNeeds(source, name, reduced), name, required));
    }
  }
});

test('concrete block and scalar needs retain the same owned success requirements', () => {
  const source = 'jobs:\n  first:\n    runs-on: ubuntu-latest\n' +
    '  second:\n    needs: first\n' +
    '  complete:\n    needs:\n      - first\n      - second\n';
  assert.deepEqual(jobNeeds(source, 'second'), ['first']);
  assert.deepEqual(requireJobNeeds(source, 'complete', ['second', 'first']), ['first', 'second']);
  assert.throws(() => requireJobNeeds(source.replace('      - second\n', ''), 'complete', ['first', 'second']));
});
