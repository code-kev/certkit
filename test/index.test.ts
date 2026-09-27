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

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'certkit-status-'));
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

    await expect(status({ caDir })).resolves.toEqual({
      caDir,
      ca: null,
      stores: [
        { store: 'macos-keychain', state: 'untrusted' },
        { store: 'windows-root', state: 'not-detected' },
        { store: 'linux-system', state: 'not-detected' },
        { store: 'nss', state: 'not-detected' },
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

  it('reports a detected store without an adapter as not-detected without running commands', async () => {
    const caDir = join(root, 'ca');
    await certificateFor(['localhost'], { caDir });
    const statePath = join(caDir, 'state.json');
    const state = JSON.parse(readFileSync(statePath, 'utf8')) as {
      pendingWrites: unknown[];
    };
    state.pendingWrites = [
      {
        store: 'nss',
        target: '/home/test/.pki/nssdb',
        sha256: 'b'.repeat(64),
        timestamp: new Date().toISOString(),
      },
    ];
    writeFileSync(statePath, `${JSON.stringify(state, null, 2)}\n`);
    vi.mocked(detect).mockResolvedValue({
      os: 'linux',
      wsl: false,
      stores: [
        { store: 'macos-keychain', detected: false },
        { store: 'windows-root', detected: false },
        { store: 'linux-system', detected: true },
        {
          store: 'nss',
          detected: true,
          targets: ['/home/test/.pki/nssdb'],
          installTargets: [],
        },
      ],
    });

    await expect(status({ caDir })).resolves.toMatchObject({
      stores: [
        { store: 'macos-keychain', state: 'not-detected' },
        { store: 'windows-root', state: 'not-detected' },
        { store: 'linux-system', state: 'not-detected' },
        {
          store: 'nss',
          state: 'unknown',
          target: '/home/test/.pki/nssdb',
          detail: 'Trust write outcome is unresolved.',
        },
      ],
    });
    expect(run).not.toHaveBeenCalled();
    expect(createMacosAdapter).not.toHaveBeenCalled();
  });
});
