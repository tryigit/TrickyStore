const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync('module/template/webroot/policy.js', 'utf8');

assert.match(source, /const MAX_POLICY_PROFILES = 64;/, 'WebUI profile limit must match PolicyState');
assert.match(source, /const MAX_PROFILE_APPLICATIONS = 256;/, 'WebUI per-profile assignment limit must match PolicyState');
assert.match(source, /const MAX_TOTAL_ASSIGNMENTS = 2048;/, 'WebUI total assignment limit must match PolicyState');
assert.match(source, /validatePolicyLimits\(source\);/, 'policy saves must reject over-limit state before normalization');

const start = source.indexOf('function safeClone(value)');
const end = source.indexOf('function transitionRequiresReboot', start);
assert.ok(start >= 0 && end > start, 'policy normalization implementation is missing');
const implementation = source.slice(start, end);

const context = { console };
vm.createContext(context);
vm.runInContext(`
  const PROFILE_FEATURES = [
    ['buildIdentity'], ['attestationIdentity'], ['telephonyIdentity'],
    ['regionIdentity'], ['identityRefresh'], ['securityPatch']
  ];
  const PATCH_COMPONENTS = [['system', 'System'], ['vendor', 'Vendor'], ['boot', 'Boot']];
  const PATCH_MODES = [
    ['device_default', 'Device default'], ['prop', 'ROM property'], ['manual', 'Manual date'],
    ['automatic', 'Automatic'], ['no', 'Omit']
  ];
  const MAX_POLICY_PROFILES = 64;
  const MAX_PROFILE_APPLICATIONS = 256;
  const MAX_TOTAL_ASSIGNMENTS = 2048;
  const MAX_PROFILE_VALUE_LENGTH = 256;
  ${implementation}
  this.normalizePolicyState = normalizePolicyState;
  this.stateForSave = stateForSave;
`, context, { filename: 'policy.js#limit-contract' });

function features() {
  return {
    buildIdentity: false,
    attestationIdentity: false,
    telephonyIdentity: false,
    regionIdentity: false,
    identityRefresh: false,
    securityPatch: false
  };
}

function securityPatch() {
  return {
    automaticThresholdMonths: 6,
    system: { mode: 'device_default' },
    vendor: { mode: 'device_default' },
    boot: { mode: 'device_default' }
  };
}

function profile(name, applicationCount) {
  return {
    name,
    applications: Array.from({ length: applicationCount }, (_, index) => `com.example.${name}.${index}`),
    template: null,
    keybox: null,
    privacy: 'inherit',
    features: {},
    securityPatch: {},
    rkpPassthrough: null,
    drmPassthrough: null
  };
}

function policy(profiles) {
  return {
    version: 2,
    features: features(),
    securityPatch: securityPatch(),
    profiles,
    activeProfile: null
  };
}

const assignments = Array.from({ length: 256 }, (_, index) => `com.example.roundtrip.${index}`);
const canonical = policy([{ ...profile('roundtrip', 0), applications: assignments }]);
const normalized = context.normalizePolicyState(canonical);
assert.equal(normalized.profiles[0].applications.length, 256, 'canonical 256-assignment profile must survive WebUI normalization');
const saved = context.stateForSave(normalized);
assert.equal(saved.profiles[0].applications.length, 256, 'canonical 256-assignment profile must survive save normalization');
assert.equal(saved.profiles[0].applications.join('\n'), assignments.join('\n'), 'policy round-trip must not drop assignments 65-256');

assert.doesNotThrow(() => context.stateForSave(policy(Array.from({ length: 64 }, (_, index) => profile(`p${index}`, 0)))));
assert.throws(
  () => context.stateForSave(policy(Array.from({ length: 65 }, (_, index) => profile(`p${index}`, 0)))),
  /at most 64 profiles/,
  '65th profile must be rejected instead of silently discarded'
);
assert.throws(
  () => context.stateForSave(policy([profile('too-many-apps', 257)])),
  /at most 256 application assignments/,
  '257th application assignment must be rejected instead of silently discarded'
);

const totalLimitProfiles = Array.from({ length: 8 }, (_, index) => profile(`full${index}`, 256));
totalLimitProfiles.push(profile('overflow', 1));
assert.throws(
  () => context.stateForSave(policy(totalLimitProfiles)),
  /at most 2048 total application assignments/,
  'global assignment overflow must fail in WebUI before backend rejection'
);

console.log('Policy WebUI/backend limit contract regression checks passed');
