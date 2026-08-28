/*
 * ecosystem.config.js — pm2 process definition.
 *
 * Not a dependency: pm2 reads this, the app never does, and nothing here is
 * installed or bundled. Start it from the project directory with
 *
 *     pm2 start ecosystem.config.js
 *
 * Paths are relative to this file, so the same config works on any host.
 */
module.exports = {
  apps: [
    {
      name: 'APEX_JediSyslogger',
      script: 'server.js',
      exec_mode: 'fork',
      instances: 1,

      // Watch the source, never the state. auth.json is rewritten on every
      // sign-in, every collector edit and every history entry; watching it would
      // restart the backend — signing everyone out — several times a minute.
      // The list is a whitelist for that reason; ignore_watch is the second belt.
      watch: [
        'server.js', 'auth.js', 'ecosystem.config.js',
        'js', 'css',
        'index.html', 'login.html', 'account.html', 'about.html',
      ],
      ignore_watch: ['auth\\.json', 'apex\\.log', '\\.git', 'node_modules', 'samples', '\\.claude'],
      watch_delay: 1000,

      autorestart: true,
      restart_delay: 2000,
      max_restarts: 20,
      time: true,

      env: {
        PORT: 8099,
        // JEDI_SECURE_COOKIE: '1',   // set this when a TLS proxy sits in front
      },
    },
  ],
};
