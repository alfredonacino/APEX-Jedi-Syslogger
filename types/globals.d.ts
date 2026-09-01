/*
 * globals.d.ts — ambient declarations so editors can typecheck this project
 * without an npm install. Nothing here ships to the browser or to Node; it
 * exists purely to describe globals the source already relies on.
 */

// The browser half attaches every module to a single `JS` namespace on window.
interface Window {
  JS: any;
}

// server.js is CommonJS on Node core modules; these stand in for @types/node.
declare module 'http';
declare module 'https';
declare module 'crypto';
declare module 'dgram';
declare module 'net';
declare module 'fs';
declare module 'path';
declare module 'readline';

declare var require: any;
declare var module: any;
declare var exports: any;
declare var __dirname: string;
declare var __filename: string;
declare var process: any;
declare var Buffer: any;
