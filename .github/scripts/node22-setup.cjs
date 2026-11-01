'use strict';

const assert = require('node:assert/strict');

function requireNode22Setup(step) {
  assert.equal((step.match(/^(?:        |      - )uses: \.\/\.github\/actions\/setup-node22$/gm) || []).length, 1,
    'one exact verified Node 22 installer is required');
  assert.equal((step.match(/^(?:        |      - )uses:/gm) || []).length, 1,
    'another installer cannot share or replace the required Node step');
  assert.equal((step.match(/^        timeout-minutes: 10$/gm) || []).length, 1,
    'Node installation has its own bounded deadline');
  assert.doesNotMatch(step, /^(?:        |      - )(?:if|continue-on-error|with):|\|\|\s*true|node-version:/m,
    'the required exact runtime cannot be skipped, weakened or overridden');
}

module.exports = {requireNode22Setup};
