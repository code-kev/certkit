#!/usr/bin/env node
// Regenerates assets/vite-example-preview-{light,dark}.png from examples/vite-app.
//
// The preview follows the reader's color scheme, so both variants are captured.
// Chrome has no CLI flag for prefers-color-scheme and the host OS setting decides
// the default, so this drives Chrome over the DevTools protocol and emulates the
// media feature. Needs Google Chrome (set CHROME to override the path) and a
// built certkit dist; the script builds certkit first.
import { spawn, spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, extname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const width = 1440;
const height = 902;
const sleep = (ms) => new Promise((done) => setTimeout(done, ms));

function chromePath() {
  const candidates = [
    process.env.CHROME,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);
  const found = candidates.find((path) => existsSync(path));
  if (!found)
    throw new Error('Google Chrome not found; set CHROME to its path.');
  return found;
}

const mime = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

function serve(dir) {
  return new Promise((ready) => {
    const server = createServer((request, response) => {
      const name =
        request.url === '/' ? 'index.html' : request.url.split('?')[0];
      const path = join(dir, decodeURIComponent(name));
      try {
        const body = readFileSync(path);
        response.writeHead(200, {
          'content-type': mime[extname(path)] ?? 'application/octet-stream',
        });
        response.end(body);
      } catch {
        response.writeHead(404).end();
      }
    });
    server.listen(0, '127.0.0.1', () => ready(server));
  });
}

async function devtoolsPort(profile) {
  const file = join(profile, 'DevToolsActivePort');
  for (let i = 0; i < 100; i++) {
    if (existsSync(file)) {
      const [port] = readFileSync(file, 'utf8').split('\n');
      if (port) return Number(port);
    }
    await sleep(100);
  }
  throw new Error('Chrome DevTools port never appeared');
}

async function pageTarget(port) {
  for (let i = 0; i < 60; i++) {
    try {
      const list = await (
        await fetch(`http://127.0.0.1:${port}/json/list`)
      ).json();
      const page = list.find((target) => target.type === 'page');
      if (page?.webSocketDebuggerUrl) return page;
    } catch {
      // endpoint not up yet
    }
    await sleep(200);
  }
  throw new Error('Chrome DevTools endpoint never became ready');
}

async function main() {
  const out = mkdtempSync(join(tmpdir(), 'certkit-preview-build-'));
  const profile = mkdtempSync(join(tmpdir(), 'certkit-preview-profile-'));
  let chrome;
  let server;
  try {
    const run = (args, cwd) =>
      spawnSync('pnpm', args, { cwd, stdio: 'inherit' });
    if (run(['build'], root).status !== 0)
      throw new Error('certkit build failed');
    const example = join(root, 'examples/vite-app');
    if (
      run(['exec', 'vite', 'build', '--outDir', out, '--emptyOutDir'], example)
        .status !== 0
    )
      throw new Error('example build failed');

    server = await serve(out);
    const page = `http://127.0.0.1:${server.address().port}/`;
    chrome = spawn(
      chromePath(),
      [
        '--headless=new',
        '--disable-gpu',
        '--hide-scrollbars',
        '--no-first-run',
        '--no-default-browser-check',
        `--window-size=${width},${height}`,
        '--remote-debugging-port=0',
        `--user-data-dir=${profile}`,
        page,
      ],
      { stdio: 'ignore' },
    );

    const target = await pageTarget(await devtoolsPort(profile));
    const ws = new WebSocket(target.webSocketDebuggerUrl);
    await new Promise((done, fail) => {
      ws.onopen = done;
      ws.onerror = fail;
    });
    let id = 0;
    const pending = new Map();
    const listeners = new Set();
    ws.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.id && pending.has(message.id)) {
        const entry = pending.get(message.id);
        pending.delete(message.id);
        if (message.error) entry.fail(new Error(JSON.stringify(message.error)));
        else entry.done(message.result);
        return;
      }
      for (const listener of [...listeners]) listener(message);
    };
    const send = (method, params = {}) =>
      new Promise((done, fail) => {
        const messageId = ++id;
        pending.set(messageId, { done, fail });
        ws.send(JSON.stringify({ id: messageId, method, params }));
      });
    const waitFor = (method) =>
      new Promise((done) => {
        const listener = (message) => {
          if (message.method === method) {
            listeners.delete(listener);
            done();
          }
        };
        listeners.add(listener);
      });

    await send('Page.enable');
    await send('Emulation.setDeviceMetricsOverride', {
      width,
      height,
      deviceScaleFactor: 1,
      mobile: false,
    });
    for (const scheme of ['light', 'dark']) {
      await send('Emulation.setEmulatedMedia', {
        features: [{ name: 'prefers-color-scheme', value: scheme }],
      });
      const loaded = waitFor('Page.loadEventFired');
      await send('Page.reload', {});
      await loaded;
      const shot = await send('Page.captureScreenshot', { format: 'png' });
      const file = join(root, 'assets', `vite-example-preview-${scheme}.png`);
      writeFileSync(file, Buffer.from(shot.data, 'base64'));
      console.log(`wrote ${file}`);
    }
    ws.close();
  } finally {
    chrome?.kill('SIGKILL');
    server?.close();
    await sleep(300);
    for (const dir of [out, profile]) {
      try {
        rmSync(dir, {
          recursive: true,
          force: true,
          maxRetries: 5,
          retryDelay: 200,
        });
      } catch {
        // Temp dirs only; never fail the capture over cleanup.
      }
    }
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
