'use strict';

const timers = require('timers');

var dateCache;
function utcDate() {
  if (!dateCache) {
    const d = new Date();
    dateCache = d.toUTCString();
    timers.enroll(utcDate, 1000 - d.getMilliseconds());
    timers._unrefActive(utcDate);
  }
  return dateCache;
}
utcDate._onTimeout = function() {
  dateCache = undefined;
};
exports.utcDate = utcDate;
