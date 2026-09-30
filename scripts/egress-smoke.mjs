import { createRequire } from 'node:module';
import { createConnection } from 'node:net';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { assertEgressDenied } from './release.mjs';

const consumerRequire = createRequire(resolve('consumer', 'package.json'));
await import(pathToFileURL(consumerRequire.resolve('certkit')));
await import(pathToFileURL(consumerRequire.resolve('certkit/vite')));

const probe = await new Promise((resolve) => {
  const socket = createConnection({ host: '1.1.1.1', port: 443 });
  socket.once('connect', () => {
    socket.destroy();
    resolve({ connected: true });
  });
  socket.once('error', (error) => resolve({ code: error.code }));
  socket.setTimeout(3000, () => {
    socket.destroy();
    resolve({ code: 'ETIMEDOUT' });
  });
});

assertEgressDenied(probe);
console.log(`outbound TCP connection denied: ${probe.code}`);
