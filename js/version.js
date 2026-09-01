/*
 * version.js — the one place the version number lives.
 *
 * The dashboard, the terminal app, the server banner and the packaging scripts
 * all read this file, so a release is a single edit here plus a git tag. Dual
 * mode, like js/qr.js: a browser global for the pages, require()-able for
 * everything that runs under Node.
 */
(function (global, factory) {
  'use strict';
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  // The JS namespace is additive, so this may land before or after data.js.
  else { global.JS = global.JS || {}; global.JS.VERSION = api.VERSION; global.JS.RELEASED = api.RELEASED; }
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  return {
    VERSION: '1.0.0',
    RELEASED: '2026-09-02',
    NAME: 'APEX JediSyslogger',
  };
});
