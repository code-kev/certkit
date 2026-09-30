import { resolveConfig as resolveVite8 } from 'vite';
import { resolveConfig as resolveVite7 } from 'vite7';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { certkit } from '../../src/integrations/vite.js';

const api = vi.hoisted(() => ({
  certificateFor: vi.fn(),
  status: vi.fn(),
  elevationImported: false,
}));

vi.mock('../../src/index.js', () => ({
  certificateFor: api.certificateFor,
  status: api.status,
}));

vi.mock('../../src/cli/elevate.js', () => {
  api.elevationImported = true;
  return {};
});

const defaultHosts = ['localhost', '127.0.0.1', '::1'];
const key = 'test-key';
const cert = 'test-cert';

type Store = {
  store: 'macos-keychain' | 'windows-root' | 'linux-system' | 'nss';
  state: 'trusted' | 'untrusted' | 'unknown' | 'not-detected';
  target?: string;
};

async function callConfig(
  config: { server?: { https?: unknown } },
  platform: NodeJS.Platform,
): Promise<unknown> {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: platform });
  try {
    const hook = certkit().config as (config: typeof config) => unknown;
    return await hook(config);
  } finally {
    if (descriptor) Object.defineProperty(process, 'platform', descriptor);
  }
}

function rows(...stores: Store[]) {
  api.status.mockResolvedValue({ stores });
}

beforeEach(() => {
  api.status.mockReset();
  api.certificateFor.mockReset().mockResolvedValue({ key, cert, caCert: 'ca' });
  rows({ store: 'nss', state: 'trusted', target: '/browser/db' });
});

afterEach(() => vi.restoreAllMocks());

describe('certkit Vite plugin', () => {
  it('exports a serve-only named plugin and uses the default hosts', () => {
    const plugin = certkit();
    expect(plugin.name).toBe('certkit');
    expect(plugin.apply).toBe('serve');
    expect(api.elevationImported).toBe(false);
    expect(api.status).not.toHaveBeenCalled();
  });

  it('does not inspect trust or mint a certificate without the HTTPS opt-in', async () => {
    await callConfig({ server: {} }, 'darwin');
    await callConfig({ server: { https: true } }, 'darwin');
    expect(api.status).not.toHaveBeenCalled();
    expect(api.certificateFor).not.toHaveBeenCalled();
  });

  it.each([
    [
      'macOS',
      'darwin',
      [
        { store: 'macos-keychain', state: 'untrusted' },
        { store: 'nss', state: 'untrusted', target: '/firefox/profile' },
      ],
    ],
    [
      'Windows',
      'win32',
      [
        { store: 'windows-root', state: 'untrusted' },
        { store: 'nss', state: 'untrusted', target: 'C:\\Firefox\\profile' },
      ],
    ],
    [
      'Linux NSS',
      'linux',
      [{ store: 'nss', state: 'untrusted', target: '/home/test/nssdb' }],
    ],
  ] as const)(
    'blocks when every detected %s browser target is untrusted',
    async (_name, platform, stores) => {
      rows(...stores);
      await expect(
        callConfig({ server: { https: {} } }, platform),
      ).rejects.toThrow(/certkit install/i);
      expect(api.certificateFor).not.toHaveBeenCalled();
    },
  );

  it.each([
    [
      'macOS',
      'darwin',
      { store: 'macos-keychain', state: 'trusted', target: 'default' },
    ],
    [
      'Windows',
      'win32',
      { store: 'windows-root', state: 'trusted', target: 'current-user' },
    ],
  ] as const)(
    'serves with HTTPS and names untrusted Firefox profiles when the %s OS store is trusted',
    async (_name, platform, osStore) => {
      rows(osStore, {
        store: 'nss',
        state: 'untrusted',
        target: '/Firefox/Profiles/stale',
      });
      const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});

      await expect(
        callConfig({ server: { https: {} } }, platform),
      ).resolves.toEqual({
        server: { https: { key, cert } },
      });
      expect(warning).toHaveBeenCalledWith(
        expect.stringContaining('/Firefox/Profiles/stale'),
      );
    },
  );

  it.each([
    [
      'macOS',
      'darwin',
      { store: 'macos-keychain', state: 'trusted', target: 'default' },
    ],
    [
      'Windows',
      'win32',
      { store: 'windows-root', state: 'trusted', target: 'current-user' },
    ],
  ] as const)(
    'names an unknown Firefox profile even when the %s OS store is trusted',
    async (_name, platform, osStore) => {
      rows(osStore, {
        store: 'nss',
        state: 'unknown',
        target: '/Firefox/Profiles/uncertain',
      });
      const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});

      await expect(
        callConfig({ server: { https: {} } }, platform),
      ).resolves.toMatchObject({
        server: { https: { key, cert } },
      });
      expect(warning).toHaveBeenCalledWith(
        expect.stringContaining('/Firefox/Profiles/uncertain'),
      );
    },
  );

  it('serves with an uncertainty warning for unknown or absent browser targets', async () => {
    rows({ store: 'nss', state: 'unknown', target: '/Firefox/profile' });
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await expect(
      callConfig({ server: { https: {} } }, 'linux'),
    ).resolves.toMatchObject({
      server: { https: { key, cert } },
    });
    expect(warning).toHaveBeenCalledWith(
      expect.stringMatching(/unknown|uncertain/i),
    );

    rows({ store: 'nss', state: 'not-detected' });
    await expect(
      callConfig({ server: { https: {} } }, 'linux'),
    ).resolves.toMatchObject({
      server: { https: { key, cert } },
    });
    expect(warning).toHaveBeenCalledWith(
      expect.stringMatching(/no browser|not detected/i),
    );

    rows();
    await expect(
      callConfig({ server: { https: {} } }, 'linux'),
    ).resolves.toMatchObject({
      server: { https: { key, cert } },
    });
  });

  it('ignores the Linux system CA store when deriving browser trust', async () => {
    rows(
      { store: 'linux-system', state: 'untrusted' },
      { store: 'nss', state: 'trusted', target: '/home/test/nssdb' },
    );
    await expect(
      callConfig({ server: { https: {} } }, 'linux'),
    ).resolves.toMatchObject({
      server: { https: { key, cert } },
    });
    expect(api.certificateFor).toHaveBeenCalledWith(defaultHosts);
  });

  it.each([
    ['Vite 7', resolveVite7],
    ['Vite 8', resolveVite8],
  ] as const)(
    'passes custom hosts and merges the result into %s resolved HTTPS config',
    async (_version, resolveConfig) => {
      const hosts = ['dev.example.test'];
      const before = { name: 'before-certkit' };
      const after = { name: 'after-certkit' };
      const resolved = await resolveConfig(
        {
          configFile: false,
          plugins: [before, certkit({ hosts }), after],
          server: { https: {} },
        },
        'serve',
        'development',
      );

      expect(resolved.plugins.map((plugin) => plugin.name)).toContain(
        'certkit',
      );
      expect(
        resolved.plugins.findIndex(
          (plugin) => plugin.name === 'before-certkit',
        ),
      ).toBeLessThan(
        resolved.plugins.findIndex((plugin) => plugin.name === 'certkit'),
      );
      expect(
        resolved.plugins.findIndex((plugin) => plugin.name === 'certkit'),
      ).toBeLessThan(
        resolved.plugins.findIndex((plugin) => plugin.name === 'after-certkit'),
      );
      expect(resolved.server.https).toMatchObject({ key, cert });
      expect(api.certificateFor).toHaveBeenCalledWith(hosts);
      expect(api.elevationImported).toBe(false);
    },
  );

  it('does not run its config hook in a production build', async () => {
    await resolveVite8(
      { configFile: false, plugins: [certkit()], server: { https: {} } },
      'build',
      'production',
    );
    expect(api.status).not.toHaveBeenCalled();
    expect(api.certificateFor).not.toHaveBeenCalled();
  });
});
