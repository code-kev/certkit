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
import { createMacosAdapter } from '../src/platforms/macos.js';
import { run } from '../src/platforms/run.js';

const mockMacosCheckTrust = vi.hoisted(() => vi.fn());

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

vi.mock('../src/platforms/run.js', () => ({ run: vi.fn() }));

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

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'certkit-status-'));
  detectMacos();
  mockMacosCheckTrust.mockResolvedValue([
    { state: 'unknown', target: 'default', detail: 'probe inconclusive' },
  ]);
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

  it('reports every detected NSS database without an adapter', async () => {
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
    expect(run).not.toHaveBeenCalled();
    expect(createMacosAdapter).not.toHaveBeenCalled();
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
});
