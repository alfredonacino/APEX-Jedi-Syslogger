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
    VERSION: '1.2.3',
    RELEASED: '2026-09-02',
    NAME: 'APEX JediSyslogger',

    // ---- Update channel ---------------------------------------------------
    // Where a build asks whether it is current, and the Ed25519 key it checks
    // the answer with. A public key is not a secret — it is *meant* to ship in
    // every copy, and it is what makes the update server untrusted: the server
    // can serve any bytes it likes, and a manifest it did not sign with the
    // matching private key is rejected before a version is even compared.
    //
    // The private half never appears in this repository, in any package, or in
    // any build log. `packaging/sign.js` reads it from JEDI_PUBLISH_KEY or from
    // a file outside the tree, and refuses to run if it does not match the key
    // below. See DOCUMENTATION.md §16.6.
    // The origin of the Apex Update Server. Paths are built from UPDATE_APP,
    // so a mirror only needs this one value changed. Baked into every artefact
    // at build time, which is why it must be right before anything is packaged.
    UPDATE_URL: 'https://atlasupdate.cybercontrol.tech',
    UPDATE_APP: 'apex-jedisyslogger-portable',
    UPDATE_PUBKEY: '5n-pji7b1FvJEpjhgpjyu8sUFL7TOcgFQ34-93PuVh0',
    UPDATE_CHANNEL: 'stable',
  };
});
