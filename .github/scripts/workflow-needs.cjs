'use strict';

const assert = require('node:assert/strict');

function jobBody(source, name) {
  assert.match(name, /^[a-zA-Z_][a-zA-Z0-9_-]*$/, 'invalid workflow job identity');
  const marker = '\n  ' + name + ':\n';
  assert.equal(source.split(marker).length - 1, 1, 'one exact workflow job required: ' + name);
  const rest = source.slice(source.indexOf(marker) + marker.length);
  const end = rest.search(/^  [a-zA-Z_][a-zA-Z0-9_-]*:\s*$/m);
  return end < 0 ? rest : rest.slice(0, end);
}

// This intentionally accepts only concrete job identities, not an expression,
// comment or a matching line in a different job. Whitespace/order and adding
// another real dependency do not change whether each required gate is present.
function jobNeeds(source, name) {
  const lines = jobBody(source, name).split('\n');
  const positions = lines.flatMap((line, index) => /^    needs:/.test(line) ? [index] : []);
  assert.equal(positions.length, 1, 'one actual needs declaration required: ' + name);
  const index = positions[0], value = lines[index].slice('    needs:'.length).trim();
  let needs;
  if (value.startsWith('[')) {
    assert.ok(value.endsWith(']'), 'incomplete concrete needs array: ' + name);
    needs = value.slice(1, -1).split(',').map(value => value.trim());
  } else if (value) {
    needs = [value];
  } else {
    needs = [];
    for (const line of lines.slice(index + 1)) {
      if (!/^      - /.test(line)) break;
      needs.push(line.slice('      - '.length).trim());
    }
  }
  assert.ok(needs.length > 0, 'empty workflow needs: ' + name);
  needs = needs.map(dependency => {
    if ((dependency.startsWith('"') && dependency.endsWith('"')) ||
        (dependency.startsWith("'") && dependency.endsWith("'"))) {
      return dependency.slice(1, -1);
    }
    return dependency;
  });
  assert.equal(new Set(needs).size, needs.length, 'duplicate workflow dependency: ' + name);
  for (const dependency of needs) {
    assert.match(dependency, /^[a-zA-Z_][a-zA-Z0-9_-]*$/, 'non-concrete workflow dependency: ' + name);
    assert.notEqual(dependency, name, 'workflow job cannot depend on itself');
    jobBody(source, dependency);
  }
  return needs;
}

function requireJobNeeds(source, name, required) {
  const actual = jobNeeds(source, name);
  assert.equal(new Set(required).size, required.length, 'duplicate required dependency policy');
  for (const dependency of required) {
    assert.ok(actual.includes(dependency), name + ' omitted required success gate: ' + dependency);
  }
  return actual;
}

module.exports = {jobBody, jobNeeds, requireJobNeeds};
