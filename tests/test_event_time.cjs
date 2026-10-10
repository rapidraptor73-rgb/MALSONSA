const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../dashboard/frontend/rsyslog.html'), 'utf8');
const functions = html.slice(html.indexOf('function normalizeIso('), html.indexOf('function renderTabs('));
const clientNow = Date.parse('2026-10-10T06:00:00.000Z');
class ClientDate extends Date { static now() { return clientNow; } }
const context = vm.createContext({Date: ClientDate, serverClockOffsetMs: 0,
  document: {getElementById: () => ({value: '300'})}});
vm.runInContext(functions, context);
const timestamp = '2026-10-10T15:03:46.082249+09:00';
assert.equal(context.eventTime({time: null, event_time: timestamp}), timestamp);
assert.equal(context.parseTime(context.eventTime({event_time: timestamp})).toISOString(), '2026-10-10T06:03:46.082Z');
assert.equal(context.eventTime({time: timestamp, event_time: 'old'}), timestamp);
assert.equal(context.eventTime({received_at: timestamp}), timestamp);
assert.equal(context.eventTime({}), '');
assert.equal(context.parseTime('invalid'), null);
const futureEvent = {event_time: '2026-10-10T15:04:00.000000+09:00'};
assert.equal(context.timeMatches(futureEvent), false);
context.updateServerClock(futureEvent.event_time, clientNow - 20, clientNow + 20);
assert.equal(context.timeMatches(futureEvent), true);
assert.equal(context.ageText(futureEvent.event_time), '0초 전');
assert.equal(context.timeMatches({time: '2026-10-10T14:50:00+09:00'}), false);
context.updateServerClock('invalid', clientNow, clientNow);
assert.equal(context.timeMatches(futureEvent), true);
console.log('Legacy timestamps, microseconds and server/client clock skew checks passed');
