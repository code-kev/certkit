import assert from 'node:assert/strict';
import { execFile as execFileCallback } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import {
  access,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import https from 'node:https';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { afterEach, describe, it } from 'vitest';
import { certificateFor } from '../../src/core/certificate.js';
import { detect } from '../../src/platforms/detect.js';
import {
  createLinuxAdapter,
  linuxAnchorTarget,
} from '../../src/platforms/linux.js';
import { createMacosAdapter } from '../../src/platforms/macos.js';
import type { RunResult } from '../../src/platforms/run.js';
import { run as nativeRun } from '../../src/platforms/run.js';

const execFile = promisify(execFileCallback);
const enabled =
  process.env.CI === 'true' &&
  process.env.GITHUB_ACTIONS === 'true' &&
  process.env.CERTKIT_TRUST_E2E === '1';
const platform = process.platform;
const supported = platform === 'linux' || platform === 'darwin';
const testTrust = enabled && supported ? describe : describe.skip;
let tempDir: string | undefined;
let cleanupError: unknown;

afterEach(async () => {
  if (cleanupError) {
    const error = cleanupError;
    cleanupError = undefined;
    throw new Error(
      `Trust e2e cleanup failed; retained artifacts at ${tempDir}`,
      {
        cause: error,
      },
    );
  }
  try {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
  } finally {
    tempDir = undefined;
  }
});

async function command(
  argv: string[],
  allowFailure = false,
): Promise<RunResult> {
  const executable = argv[0];
  assert(executable, 'command requires an executable');
  try {
    const { stdout, stderr } = await execFile(executable, argv.slice(1), {
      encoding: 'utf8',
      timeout: 30_000,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as NodeJS.ErrnoException & {
      stdout?: string;
      stderr?: string;
      code?: number;
    };
    if (allowFailure && typeof failure.code === 'number')
      return {
        code: failure.code,
        stdout: failure.stdout ?? '',
        stderr: failure.stderr ?? '',
      };
    throw error;
  }
}

async function createFixture() {
  const dir = await mkdtemp(path.join(tmpdir(), 'certkit-trust-e2e-'));
  tempDir = dir;
  const caDir = path.join(dir, 'ca');
  const caCertPath = path.join(caDir, 'ca-cert.pem');
  const leafCertPath = path.join(dir, 'leaf.pem');
  const bundle = await certificateFor(['localhost'], { caDir });
  assert.equal(await readFile(caCertPath, 'utf8'), bundle.caCert);
  await writeFile(leafCertPath, bundle.cert, { flag: 'wx' });
  return { dir, caDir, caCertPath, leafCertPath, bundle };
}

async function startTlsServer(cert: string, key: string) {
  const server = https.createServer({ cert, key }, (_request, response) => {
    response.end('certkit trust e2e\n');
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert(address && typeof address === 'object');
  return { server, url: `https://localhost:${address.port}/` };
}

async function expectCurl(url: string, expectedSuccess: boolean) {
  const { port } = new URL(url);
  const result = await command(
    [
      'curl',
      '--ipv4',
      '--resolve',
      `localhost:${port}:127.0.0.1`,
      '--noproxy',
      '*',
      '--fail',
      '--silent',
      '--show-error',
      url,
    ],
    true,
  );
  assert.equal(
    result.code === 0,
    expectedSuccess,
    `curl ${expectedSuccess ? 'did not trust' : 'unexpectedly trusted'} the test CA: ${result.stderr}`,
  );
  if (!expectedSuccess)
    assert.equal(
      result.code,
      60,
      `expected curl certificate failure: ${result.stderr}`,
    );
  if (expectedSuccess) assert.equal(result.stdout, 'certkit trust e2e\n');
}

function parseKeychains(stdout: string): string[] {
  const lines = stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  assert(lines.every((line) => line.startsWith('"') && line.endsWith('"')));
  return lines.map((line) => line.slice(1, -1).replaceAll('\\"', '"'));
}

testTrust('native CA trust install and uninstall', () => {
  it('uses production adapters and removes every trust artifact', async () => {
    await command(['openssl', 'version']);
    const { dir, caCertPath, leafCertPath, bundle } = await createFixture();
    await command([
      'openssl',
      'verify',
      '-purpose',
      'sslserver',
      '-CAfile',
      caCertPath,
      leafCertPath,
    ]);

    if (platform === 'linux') {
      await linuxTrust({ caCertPath, leafCertPath, bundle });
    } else {
      await macosTrust({ dir, caCertPath, leafCertPath, bundle });
    }
  }, 120_000);
});

async function linuxTrust({
  caCertPath,
  leafCertPath,
  bundle,
}: {
  caCertPath: string;
  leafCertPath: string;
  bundle: Awaited<ReturnType<typeof certificateFor>>;
}) {
  assert.equal(
    (await command(['sudo', '-n', 'true'], true)).code,
    0,
    'CI needs passwordless sudo',
  );
  const environment = await detect();
  const store = environment.stores.find(
    (item) => item.store === 'linux-system',
  );
  assert.equal(environment.os, 'linux');
  assert(store?.detected, 'Linux system CA store is unavailable');
  assert.equal(
    store.detail,
    'update-ca-certificates',
    'expected update-ca-certificates in CI',
  );
  const mechanism = store.detail;
  const target = linuxAnchorTarget(caCertPath, mechanism);
  const adapter = createLinuxAdapter({
    caCertPath,
    run: nativeRun,
    elevate: async (argv) => {
      const result = await command(['sudo', '-n', '--', ...argv], true);
      if (result.code !== 0)
        throw new Error(`sudo ${argv[0]} failed: ${result.stderr}`);
    },
  });
  let installAttempted = false;
  const { server, url } = await startTlsServer(bundle.cert, bundle.key);
  try {
    assert.equal(
      (await adapter.checkTrust(bundle.caCert, environment))[0]?.state,
      'untrusted',
    );
    assert.equal(
      await adapter.inspectInstalled(bundle.caCert, target, mechanism),
      'absent',
    );
    await expectCurl(url, false);
    installAttempted = true;
    assert.deepEqual(await adapter.install(caCertPath, target, mechanism), {
      state: 'verified',
    });
    assert.equal(
      await adapter.inspectInstalled(bundle.caCert, target, mechanism),
      'present',
    );
    assert.equal(
      (await adapter.checkTrust(bundle.caCert, environment))[0]?.state,
      'trusted',
    );
    await command([
      'openssl',
      'verify',
      '-purpose',
      'sslserver',
      '-CAfile',
      caCertPath,
      leafCertPath,
    ]);
    await expectCurl(url, true);
    await adapter.uninstall(bundle.caCert, target, mechanism);
    installAttempted = false;
    assert.equal(
      await adapter.inspectInstalled(bundle.caCert, target, mechanism),
      'absent',
    );
    assert.equal(
      (await adapter.checkTrust(bundle.caCert, environment))[0]?.state,
      'untrusted',
    );
    await expectCurl(url, false);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    if (installAttempted) {
      try {
        await adapter.uninstall(bundle.caCert, target, mechanism);
      } catch (error) {
        cleanupError = error;
      }
    }
    try {
      const remaining = await adapter.inspectInstalled(
        bundle.caCert,
        target,
        mechanism,
      );
      assert.equal(
        remaining,
        'absent',
        `Linux CA anchor remains after cleanup: ${remaining}`,
      );
    } catch (error) {
      cleanupError ??= error;
    }
  }
}

async function macosTrust({
  dir,
  caCertPath,
  leafCertPath,
  bundle,
}: {
  dir: string;
  caCertPath: string;
  leafCertPath: string;
  bundle: Awaited<ReturnType<typeof certificateFor>>;
}) {
  for (const tool of ['security', 'openssl'])
    assert.equal(
      (await command(['which', tool], true)).code,
      0,
      `missing oracle: ${tool}`,
    );
  const keychainPath = path.join(await realpath(dir), 'throwaway.keychain-db');
  const originalKeychains = parseKeychains(
    (await nativeRun(['security', 'list-keychains', '-d', 'user'])).stdout,
  );
  let keychainCreated = false;
  let installAttempted = false;
  let changedKeychainList = false;
  const adapter = createMacosAdapter({
    caCertPath,
    keychainPath,
    run: async (argv) => {
      console.log(`macOS native trust command: ${argv[0]} ${argv[1]}`);
      return nativeRun(argv, { timeoutMs: 30_000 });
    },
  });
  const environment = await detect();
  try {
    await command(['security', 'create-keychain', '-p', '', keychainPath]);
    keychainCreated = true;
    await access(keychainPath);
    await command(['security', 'unlock-keychain', '-p', '', keychainPath]);
    await command([
      'security',
      'set-keychain-settings',
      '-lut',
      '21600',
      keychainPath,
    ]);
    await command([
      'security',
      'list-keychains',
      '-d',
      'user',
      '-s',
      ...originalKeychains,
      keychainPath,
    ]);
    changedKeychainList = true;
    const visibleKeychains = parseKeychains(
      (await nativeRun(['security', 'list-keychains', '-d', 'user'])).stdout,
    );
    assert(
      visibleKeychains.includes(keychainPath),
      `throwaway keychain missing from native search list: ${JSON.stringify(visibleKeychains)}`,
    );

    const initialTrust = await adapter.checkTrust(bundle.caCert, environment);
    assert.equal(
      initialTrust[0]?.state,
      'untrusted',
      JSON.stringify(initialTrust),
    );
    assert.equal(
      await adapter.inspectInstalled(bundle.caCert, 'default'),
      'absent',
    );
    installAttempted = true;
    assert.deepEqual(await adapter.install(caCertPath, 'default'), {
      state: 'verified',
    });
    assert.equal(
      await adapter.inspectInstalled(bundle.caCert, 'default'),
      'present',
    );
    const trust = await adapter.checkTrust(bundle.caCert, environment);
    assert.equal(trust[0]?.state, 'trusted', JSON.stringify(trust));
    await command([
      'openssl',
      'verify',
      '-purpose',
      'sslserver',
      '-CAfile',
      caCertPath,
      leafCertPath,
    ]);
    const native = await command(
      ['security', 'verify-cert', '-c', caCertPath, '-p', 'ssl', '-l', '-L'],
      true,
    );
    assert.equal(native.code, 0, native.stderr || native.stdout);

    await adapter.uninstall(bundle.caCert, 'default');
    installAttempted = false;
    assert.equal(
      await adapter.inspectInstalled(bundle.caCert, 'default'),
      'absent',
    );
    assert.equal(
      (await adapter.checkTrust(bundle.caCert, environment))[0]?.state,
      'untrusted',
    );
    const after = await command(
      ['security', 'verify-cert', '-c', caCertPath, '-p', 'ssl', '-l', '-L'],
      true,
    );
    assert.notEqual(after.code, 0, 'macOS still trusts the removed CA');
  } finally {
    if (installAttempted) {
      try {
        await adapter.uninstall(bundle.caCert, 'default');
      } catch (error) {
        cleanupError = error;
      }
    }
    // User-domain trust outlives the keychain, so remove it before deleting that keychain.
    try {
      await command(['security', 'remove-trusted-cert', caCertPath], true);
    } catch (error) {
      cleanupError ??= error;
    }
    try {
      const exportPath = path.join(dir, 'user-trust.plist');
      const exported = await command(
        ['security', 'trust-settings-export', exportPath],
        true,
      );
      const output = `${exported.stdout}\n${exported.stderr}`;
      if (exported.code !== 0) {
        assert.match(output, /No Trust Settings were found/i);
      } else {
        const plist = await readFile(exportPath, 'utf8');
        assert.match(plist, /<plist\b[\s\S]*<dict\b/i);
        const sha1 = new X509Certificate(bundle.caCert).fingerprint
          .replaceAll(':', '')
          .toLowerCase();
        const hashes = [...plist.matchAll(/<key>\s*([\da-f]{40})\s*<\/key>/gi)];
        assert(
          !hashes.some(([, hash]) => hash?.toLowerCase() === sha1),
          'macOS user trust settings retain the CA',
        );
      }
    } catch (error) {
      cleanupError ??= error;
    }
    if (changedKeychainList) {
      try {
        await command([
          'security',
          'list-keychains',
          '-d',
          'user',
          '-s',
          ...originalKeychains,
        ]);
      } catch (error) {
        cleanupError ??= error;
      }
    }
    if (keychainCreated) {
      try {
        await command(['security', 'delete-keychain', keychainPath]);
      } catch (error) {
        cleanupError ??= error;
      }
    }
    try {
      const residual = await command(
        ['security', 'verify-cert', '-c', caCertPath, '-p', 'ssl', '-l', '-L'],
        true,
      );
      assert.notEqual(
        residual.code,
        0,
        'macOS still accepts the throwaway CA after cleanup',
      );
    } catch (error) {
      cleanupError ??= error;
    }
  }
}
