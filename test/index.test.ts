import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { certificateFor, status } from '../src/index.js';
import { detect } from '../src/platforms/detect.js';
import { createLinuxAdapter } from '../src/platforms/linux.js';
import { createMacosAdapter } from '../src/platforms/macos.js';
import { createNssAdapter } from '../src/platforms/nss.js';
import { run } from '../src/platforms/run.js';
import { createWindowsAdapter } from '../src/platforms/windows.js';

const mockMacosCheckTrust = vi.hoisted(() => vi.fn());
const mockWindowsCheckTrust = vi.hoisted(() => vi.fn());
const mockLinuxCheckTrust = vi.hoisted(() => vi.fn());
const mockNssCheckTrust = vi.hoisted(() => vi.fn());

vi.mock('../src/platforms/detect.js', () => ({
  detect: vi.fn(async () => ({
    os: 'macos',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: true },
      { store: 'windows-root', detected: false },
      { store: 'linux-system', detected: false },
      { store: 'nss', detected: false, targets: [], installTargets: [] },
    ],
  })),
}));

vi.mock('../src/platforms/macos.js', () => ({
  createMacosAdapter: vi.fn(() => ({
    id: 'macos-keychain',
    checkTrust: mockMacosCheckTrust,
    install: vi.fn(),
    uninstall: vi.fn(),
  })),
}));

vi.mock('../src/platforms/windows.js', () => ({
  createWindowsAdapter: vi.fn(() => ({
    id: 'windows-root',
    checkTrust: mockWindowsCheckTrust,
    inspectInstalled: vi.fn(),
    install: vi.fn(),
    uninstall: vi.fn(),
  })),
}));

vi.mock('../src/platforms/linux.js', () => ({
  createLinuxAdapter: vi.fn(() => ({
    id: 'linux-system',
    checkTrust: mockLinuxCheckTrust,
    inspectInstalled: vi.fn(),
    install: vi.fn(),
    uninstall: vi.fn(),
  })),
}));

vi.mock('../src/platforms/nss.js', () => ({
  createNssAdapter: vi.fn(() => ({
    id: 'nss',
    checkTrust: mockNssCheckTrust,
    inspectInstalled: vi.fn(),
    install: vi.fn(),
    uninstall: vi.fn(),
  })),
}));

vi.mock('../src/platforms/run.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/platforms/run.js')>()),
  run: vi.fn(),
}));

let root = '';
const nssTargets = [
  '/home/test/.pki/nssdb',
  '/home/test/.mozilla/firefox/profile.default',
];

function detectLinuxNss(targets: string[] = nssTargets): void {
  vi.mocked(detect).mockResolvedValue({
    os: 'linux',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: false },
      { store: 'windows-root', detected: false },
      { store: 'linux-system', detected: false },
      {
        store: 'nss',
        detected: targets.length > 0,
        targets,
        installTargets: [],
      },
    ],
  });
}

function detectMacos(): void {
  vi.mocked(detect).mockResolvedValue({
    os: 'macos',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: true },
      { store: 'windows-root', detected: false },
      { store: 'linux-system', detected: false },
      { store: 'nss', detected: false, targets: [], installTargets: [] },
    ],
  });
}

function detectWindows(): void {
  vi.mocked(detect).mockResolvedValue({
    os: 'windows',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: false },
      { store: 'windows-root', detected: true },
      { store: 'linux-system', detected: false },
      { store: 'nss', detected: false, targets: [], installTargets: [] },
    ],
  });
}

function detectLinuxSystem(): void {
  vi.mocked(detect).mockResolvedValue({
    os: 'linux',
    wsl: false,
    stores: [
      { store: 'macos-keychain', detected: false },
      { store: 'windows-root', detected: false },
      {
        store: 'linux-system',
        detected: true,
        detail: 'update-ca-certificates',
      },
      { store: 'nss', detected: false, targets: [], installTargets: [] },
    ],
  });
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'certkit-status-'));
  detectMacos();
  mockMacosCheckTrust.mockResolvedValue([
    { state: 'unknown', target: 'default', detail: 'probe inconclusive' },
  ]);
  mockNssCheckTrust.mockResolvedValue([]);
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
  vi.clearAllMocks();
});

describe('status', () => {
  it('reports detected stores untrusted without creating a missing CA directory', async () => {
    const caDir = join(root, 'missing-ca');
    detectLinuxNss();

    await expect(status({ caDir })).resolves.toEqual({
      caDir,
      ca: null,
      stores: [
        { store: 'macos-keychain', state: 'not-detected' },
        { store: 'windows-root', state: 'not-detected' },
        { store: 'linux-system', state: 'not-detected' },
        ...nssTargets.map((target) => ({
          store: 'nss',
          state: 'untrusted',
          target,
        })),
      ],
    });
    expect(existsSync(caDir)).toBe(false);
    expect(createMacosAdapter).not.toHaveBeenCalled();
  });

  it('returns validated CA metadata and preserves adapter uncertainty', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    const statePath = join(caDir, 'state.json');
    const state = JSON.parse(readFileSync(statePath, 'utf8')) as {
      ca: { subject: string; serial: string; expiresAt: string };
      pendingWrites: unknown[];
    };
    state.pendingWrites = [
      {
        store: 'macos-keychain',
        target: 'default',
        sha256: 'a'.repeat(64),
        timestamp: new Date().toISOString(),
      },
    ];
    writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
    const beforeStatus = readFileSync(statePath);

    await expect(status({ caDir })).resolves.toEqual({
      caDir,
      ca: {
        subject: state.ca.subject,
        serial: state.ca.serial,
        expiresAt: state.ca.expiresAt,
      },
      stores: [
        {
          store: 'macos-keychain',
          state: 'unknown',
          target: 'default',
          detail: 'probe inconclusive; trust write outcome is unresolved.',
        },
        { store: 'windows-root', state: 'not-detected' },
        { store: 'linux-system', state: 'not-detected' },
        { store: 'nss', state: 'not-detected' },
      ],
    });
    expect(readFileSync(statePath)).toEqual(beforeStatus);
    expect(createMacosAdapter).toHaveBeenCalledOnce();
  });

  it('instructs uninstall for a CA already retiring', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    const statePath = join(caDir, 'state.json');
    const state = JSON.parse(readFileSync(statePath, 'utf8')) as {
      phase: string;
    };
    state.phase = 'retiring';
    writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);

    await expect(status({ caDir })).rejects.toMatchObject({
      name: 'CertkitError',
      code: 'CA_UNREADABLE',
      message: expect.stringContaining('certkit uninstall'),
    });
  });

  it('passes an adapter not-detected result through unchanged', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    mockMacosCheckTrust.mockResolvedValue([
      {
        state: 'not-detected',
        target: 'default',
        detail: 'No keychain detected.',
      },
    ]);

    await expect(status({ caDir })).resolves.toMatchObject({
      stores: [
        {
          store: 'macos-keychain',
          state: 'not-detected',
          target: 'default',
          detail: 'No keychain detected.',
        },
        { store: 'windows-root', state: 'not-detected' },
        { store: 'linux-system', state: 'not-detected' },
        { store: 'nss', state: 'not-detected' },
      ],
    });
  });

  it('preserves and rejects broken CA material', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    const keyPath = join(caDir, 'ca-key.pem');
    writeFileSync(keyPath, 'broken');

    await expect(status({ caDir })).rejects.toMatchObject({
      name: 'CertkitError',
      code: 'CA_UNREADABLE',
    });
    expect(readFileSync(keyPath, 'utf8')).toBe('broken');
  });

  it('checks every detected NSS database through the read-only adapter', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    detectLinuxNss();
    mockNssCheckTrust.mockResolvedValue([
      { state: 'trusted', target: nssTargets[0] },
      {
        state: 'untrusted',
        target: nssTargets[1],
        detail: 'present without SSL trust',
      },
    ]);

    const report = await status({ caDir });

    expect(report.stores).toContainEqual({
      store: 'nss',
      state: 'trusted',
      target: nssTargets[0],
    });
    expect(report.stores).toContainEqual({
      store: 'nss',
      state: 'untrusted',
      target: nssTargets[1],
      detail: 'present without SSL trust',
    });
    expect(createNssAdapter).toHaveBeenCalledWith({ run });
    expect(mockNssCheckTrust).toHaveBeenCalledOnce();
    expect(run).not.toHaveBeenCalled();
    expect(createMacosAdapter).not.toHaveBeenCalled();
  });

  it('keeps every detected NSS database not-detected when the adapter has no results', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    detectLinuxNss();

    await expect(status({ caDir })).resolves.toMatchObject({
      stores: [
        { store: 'macos-keychain', state: 'not-detected' },
        { store: 'windows-root', state: 'not-detected' },
        { store: 'linux-system', state: 'not-detected' },
        ...nssTargets.map((target) => ({
          store: 'nss',
          state: 'not-detected',
          target,
        })),
      ],
    });
    expect(mockNssCheckTrust).toHaveBeenCalledOnce();
  });

  it('keeps other detected NSS databases when one target has a pending write', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    const statePath = join(caDir, 'state.json');
    const state = JSON.parse(readFileSync(statePath, 'utf8')) as {
      pendingWrites: unknown[];
    };
    state.pendingWrites = [
      {
        store: 'nss',
        target: nssTargets[0],
        sha256: 'b'.repeat(64),
        timestamp: new Date().toISOString(),
      },
    ];
    writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
    detectLinuxNss();

    await expect(status({ caDir })).resolves.toMatchObject({
      stores: [
        { store: 'macos-keychain', state: 'not-detected' },
        { store: 'windows-root', state: 'not-detected' },
        { store: 'linux-system', state: 'not-detected' },
        {
          store: 'nss',
          state: 'unknown',
          target: nssTargets[0],
          detail: 'Trust write outcome is unresolved.',
        },
        { store: 'nss', state: 'not-detected', target: nssTargets[1] },
      ],
    });
    expect(run).not.toHaveBeenCalled();
    expect(createMacosAdapter).not.toHaveBeenCalled();
  });

  it('reports pending NSS targets that are no longer detected', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    const statePath = join(caDir, 'state.json');
    const state = JSON.parse(readFileSync(statePath, 'utf8')) as {
      pendingWrites: unknown[];
    };
    state.pendingWrites = [
      {
        store: 'nss',
        target: '/home/test/removed-profile',
        sha256: 'c'.repeat(64),
        timestamp: new Date().toISOString(),
      },
    ];
    writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
    detectLinuxNss();

    await expect(status({ caDir })).resolves.toMatchObject({
      stores: [
        { store: 'macos-keychain', state: 'not-detected' },
        { store: 'windows-root', state: 'not-detected' },
        { store: 'linux-system', state: 'not-detected' },
        ...nssTargets.map((target) => ({
          store: 'nss',
          state: 'not-detected',
          target,
        })),
        {
          store: 'nss',
          state: 'unknown',
          target: '/home/test/removed-profile',
          detail: 'Trust write outcome is unresolved.',
        },
      ],
    });
  });

  it('uses the Windows Root adapter for detected Windows status', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    detectWindows();
    mockWindowsCheckTrust.mockResolvedValue([
      { state: 'trusted', target: 'default' },
    ]);

    const report = await status({ caDir });

    expect(report.stores).toContainEqual({
      store: 'windows-root',
      state: 'trusted',
      target: 'default',
    });
    expect(createWindowsAdapter).toHaveBeenCalled();
  });

  it('uses the Linux system adapter for detected Linux status', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    detectLinuxSystem();
    mockLinuxCheckTrust.mockResolvedValue([
      {
        state: 'trusted',
        target: '/usr/local/share/ca-certificates/certkit-fixture.crt',
      },
    ]);

    const report = await status({ caDir });

    expect(report.stores).toContainEqual({
      store: 'linux-system',
      state: 'trusted',
      target: '/usr/local/share/ca-certificates/certkit-fixture.crt',
    });
    expect(createLinuxAdapter).toHaveBeenCalledWith({
      caCertPath: join(caDir, 'ca-cert.pem'),
      run,
    });
  });

  it('reports a detected system store as untrusted when no CA exists', async () => {
    const caDir = join(root, 'missing-ca');
    detectMacos();

    const report = await status({ caDir });

    expect(report.stores).toContainEqual({
      store: 'macos-keychain',
      state: 'untrusted',
    });
    expect(createMacosAdapter).not.toHaveBeenCalled();
  });

  it('handles an NSS store detected without targets', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    vi.mocked(detect).mockResolvedValue({
      os: 'linux',
      wsl: false,
      stores: [
        { store: 'macos-keychain', detected: false },
        { store: 'windows-root', detected: false },
        { store: 'linux-system', detected: false },
        { store: 'nss', detected: true },
      ],
    });

    const report = await status({ caDir });

    expect(report.stores).toContainEqual({
      store: 'nss',
      state: 'not-detected',
    });
    expect(mockNssCheckTrust).toHaveBeenCalledOnce();
  });

  it('refuses to elevate during status', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    vi.mocked(createMacosAdapter).mockImplementationOnce((options) => ({
      id: 'macos-keychain',
      checkTrust: async () => {
        await options.elevate?.([]);
        return [];
      },
      install: vi.fn(),
      uninstall: vi.fn(),
    }));

    await expect(status({ caDir })).rejects.toThrow('status cannot elevate');
  });
});

describe('reflect-metadata', () => {
  it('loads the side-effect module and installs Reflect metadata', async () => {
    const module = await import('../src/reflect-metadata.js');

    expect(Object.keys(module)).toEqual([]);
    const metadata = Reflect as unknown as { getMetadata?: unknown };
    expect(typeof metadata.getMetadata).toBe('function');
  });
});
