'use strict';

const assert = require('node:assert/strict');
// Retained to audit receipts from the retired fork diagnostic workflow.
const finalRequiredNeeds = [
  'ownership', 'native-x86-oracles', 'sdk-priority', 'arm64-fallback-cross-priority',
  'lock-native-priority', 'unlocked-rmw-native-priority', 'vector-value-fault-priority',
  'packed-conversion-native-complete', 'packed-reduction-native-complete', 'complete-windows',
];

// Scheduling Windows after a failed predecessor discovers its real failures;
// it cannot supply success for that predecessor. GitHub's current-run needs
// observations remain the only input, never a job's self-reported outputs.
function qualifyDiagnosticNeeds(needs) {
  assert.ok(needs && typeof needs === 'object' && !Array.isArray(needs),
    'missing actual diagnostic dependency observations');
  assert.deepEqual(Object.keys(needs).sort(), finalRequiredNeeds.slice().sort(),
    'diagnostic qualification requires every original gate and complete Windows');
  for (const name of finalRequiredNeeds) {
    const observation = needs[name];
    assert.ok(observation && typeof observation === 'object' && !Array.isArray(observation),
      'malformed actual dependency result: ' + name);
    assert.ok(Object.hasOwn(observation, 'result'), 'absent actual dependency result: ' + name);
    assert.equal(observation.result, 'success', 'required diagnostic gate did not succeed: ' + name);
  }
  return {schema: 1, successfulJobs: finalRequiredNeeds.slice()};
}

module.exports = {qualifyDiagnosticNeeds};
if (require.main === module) {
  const input = process.env.DIAGNOSTIC_NEEDS_JSON;
  assert.equal(typeof input, 'string', 'actual GitHub needs context is required');
  const result = qualifyDiagnosticNeeds(JSON.parse(input));
  process.stdout.write(JSON.stringify(result) + '\n');
}
