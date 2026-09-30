import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createCommand } from '../../src/cli/commands/create.js';
import { setGlobalOptions } from '../../src/cli/options.js';

const roots: string[] = [];
let previousHome: string | undefined;

function fixture(): string {
  const root = mkdtempSync(join(tmpdir(), 'certkit-create-command-'));
  roots.push(root);
  return root;
}

function home(root: string): string {
  process.env.CERTKIT_HOME = join(root, 'ca');
  const outputDir = join(root, 'out');
  mkdirSync(outputDir);
  return outputDir;
}

async function invoke(args: Record<string, unknown>): Promise<void> {
  await createCommand.run?.({
    args: { _: [], ...args },
    cmd: createCommand,
    rawArgs: [],
    data: {},
  } as never);
}

function output(): { stdout: string[]; stderr: string[] } {
  const stdout: string[] = [];
  const stderr: string[] = [];
  vi.spyOn(console, 'log').mockImplementation((...values) => {
    stdout.push(values.join(' '));
  });
  vi.spyOn(console, 'error').mockImplementation((...values) => {
    stderr.push(values.join(' '));
  });
  return { stdout, stderr };
}

beforeEach(() => {
  previousHome = process.env.CERTKIT_HOME;
  process.exitCode = 0;
  setGlobalOptions({});
});

afterEach(() => {
  vi.restoreAllMocks();
  if (previousHome === undefined) delete process.env.CERTKIT_HOME;
  else process.env.CERTKIT_HOME = previousHome;
  process.exitCode = 0;
  setGlobalOptions({});
  for (const root of roots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe('create command runner', () => {
  it('writes a certificate with JSON paths for wildcard, DNS, and IP names', async () => {
    const outputDir = home(fixture());
    const result = output();

    await invoke({
      _: ['*.example.com', 'app.test', '127.0.0.1'],
      output: outputDir,
      json: true,
      'validity-days': '30',
    });

    expect(process.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout[0] ?? '') as {
      schemaVersion: number;
      names: string[];
      files: { cert: string; key: string };
    };
    expect(parsed).toEqual({
      schemaVersion: 1,
      names: ['*.example.com', 'app.test', '127.0.0.1'],
      files: {
        cert: join(outputDir, '_wildcard.example.com+2.pem'),
        key: join(outputDir, '_wildcard.example.com+2-key.pem'),
      },
    });
    expect(readFileSync(parsed.files.cert, 'utf8')).toContain(
      '-----BEGIN CERTIFICATE-----',
    );
    expect(readFileSync(parsed.files.key, 'utf8')).toContain(
      '-----BEGIN PRIVATE KEY-----',
    );
    // Windows keys are protected by ACL, not mode bits.
    if (process.platform !== 'win32')
      expect(statSync(parsed.files.key).mode & 0o777).toBe(0o600);
  });

  it('prints human output and sanitizes a reserved Windows name', async () => {
    const outputDir = home(fixture());
    const result = output();

    await invoke({ _: ['con'], output: outputDir });

    expect(process.exitCode).toBe(0);
    expect(result.stdout).toEqual([
      `Created certificate: ${JSON.stringify(join(outputDir, '_con.pem'))}`,
      `Created private key: ${JSON.stringify(join(outputDir, '_con-key.pem'))}`,
    ]);
    expect(existsSync(join(outputDir, '_con.pem'))).toBe(true);
  });

  it('defaults the output directory to the process cwd', async () => {
    const outputDir = home(fixture());
    vi.spyOn(process, 'cwd').mockReturnValue(outputDir);
    const result = output();

    await invoke({ _: ['localhost'], json: true });

    expect(process.exitCode).toBe(0);
    expect(JSON.parse(result.stdout[0] ?? '')).toEqual({
      schemaVersion: 1,
      names: ['localhost'],
      files: {
        cert: join(outputDir, 'localhost.pem'),
        key: join(outputDir, 'localhost-key.pem'),
      },
    });
    expect(existsSync(join(outputDir, 'localhost-key.pem'))).toBe(true);
  });

  it('honors the global --json option without a command flag', async () => {
    const outputDir = home(fixture());
    setGlobalOptions({ json: true });
    const result = output();

    await invoke({ _: ['localhost'], output: outputDir });

    expect(process.exitCode).toBe(0);
    expect(JSON.parse(result.stdout[0] ?? '')).toEqual({
      schemaVersion: 1,
      names: ['localhost'],
      files: {
        cert: join(outputDir, 'localhost.pem'),
        key: join(outputDir, 'localhost-key.pem'),
      },
    });
  });

  it('overwrites existing outputs with --force', async () => {
    const outputDir = home(fixture());
    const cert = join(outputDir, 'localhost.pem');
    const key = join(outputDir, 'localhost-key.pem');
    writeFileSync(cert, 'old certificate');
    writeFileSync(key, 'old key');
    output();

    await invoke({ _: ['localhost'], output: outputDir, force: true });

    expect(process.exitCode).toBe(0);
    expect(readFileSync(cert, 'utf8')).toContain('-----BEGIN CERTIFICATE-----');
    expect(readFileSync(key, 'utf8')).toContain('-----BEGIN PRIVATE KEY-----');
  });

  it.each(['0', '826', '1.5', 'abc'])(
    'exits 2 for invalid validity days %s',
    async (validity) => {
      const root = fixture();
      const outputDir = home(root);
      const result = output();

      await invoke({
        _: ['localhost'],
        output: outputDir,
        'validity-days': validity,
      });

      expect(process.exitCode).toBe(2);
      expect(result.stderr).toEqual([
        'certkit: INVALID_OPTIONS: Validity days must be an integer between 1 and 825.',
      ]);
      expect(existsSync(join(root, 'ca'))).toBe(false);
    },
  );

  it('exits 2 for an invalid name', async () => {
    const outputDir = home(fixture());
    const result = output();

    await invoke({ _: ['bad name'], output: outputDir });

    expect(process.exitCode).toBe(2);
    expect(result.stderr).toEqual([
      'certkit: INVALID_NAME: Invalid name: bad name',
    ]);
  });

  it('exits 2 without names', async () => {
    home(fixture());
    const result = output();

    await invoke({ _: [] });

    expect(process.exitCode).toBe(2);
    expect(result.stderr).toEqual([
      'certkit: INVALID_NAME: At least one name is required.',
    ]);
  });

  it('exits 2 for more than 100 names', async () => {
    const outputDir = home(fixture());
    const result = output();

    await invoke({
      _: Array.from({ length: 101 }, (_, i) => `host${i}.test`),
      output: outputDir,
    });

    expect(process.exitCode).toBe(2);
    expect(result.stderr[0]).toContain('certkit: NAME_LIMIT:');
  });

  it('exits 2 for a missing output directory', async () => {
    const root = fixture();
    home(root);
    const result = output();

    await invoke({ _: ['localhost'], output: join(root, 'missing') });

    expect(process.exitCode).toBe(2);
    expect(result.stderr[0]).toContain(
      'certkit: INVALID_OPTIONS: Output directory must already exist:',
    );
  });

  it('exits 2 when the output path is a file', async () => {
    const root = fixture();
    home(root);
    const file = join(root, 'file');
    writeFileSync(file, 'not a directory');
    const result = output();

    await invoke({ _: ['localhost'], output: file });

    expect(process.exitCode).toBe(2);
    expect(result.stderr[0]).toContain(
      'certkit: INVALID_OPTIONS: Output directory must already exist:',
    );
  });

  it('reports a non-Certkit failure with the generic CLI error', async () => {
    const outputDir = home(fixture());
    const result = output();

    await invoke({ _: [42], output: outputDir });

    expect(process.exitCode).toBe(1);
    expect(result.stderr).toEqual([
      'certkit: CLI_ERROR: Could not create certificate files.',
    ]);
  });

  it('reports an existing output without --force and leaves both files intact', async () => {
    const outputDir = home(fixture());
    const cert = join(outputDir, 'localhost.pem');
    const key = join(outputDir, 'localhost-key.pem');
    writeFileSync(cert, 'old certificate');
    writeFileSync(key, 'old key');
    const result = output();

    await invoke({ _: ['localhost'], output: outputDir });

    expect(process.exitCode).toBe(1);
    expect(result.stderr[0]).toContain(
      `certkit: CA_UNREADABLE: Output already exists: ${cert}, ${key}. Use --force to overwrite.`,
    );
    expect(readFileSync(cert, 'utf8')).toBe('old certificate');
    expect(readFileSync(key, 'utf8')).toBe('old key');
  });

  it('reports a collision as pure JSON with the operational exit code', async () => {
    const outputDir = home(fixture());
    writeFileSync(join(outputDir, 'localhost.pem'), 'old certificate');
    const result = output();

    await invoke({ _: ['localhost'], output: outputDir, json: true });

    expect(process.exitCode).toBe(1);
    expect(JSON.parse(result.stdout[0] ?? '')).toEqual({
      schemaVersion: 1,
      error: {
        code: 'CA_UNREADABLE',
        message: expect.stringContaining('Output already exists'),
      },
    });
    expect(result.stderr).toEqual([]);
  });

  it('reports invalid options as pure JSON with the usage exit code', async () => {
    const outputDir = home(fixture());
    const result = output();

    await invoke({
      _: ['localhost'],
      output: outputDir,
      json: true,
      'validity-days': '0',
    });

    expect(process.exitCode).toBe(2);
    expect(JSON.parse(result.stdout[0] ?? '')).toEqual({
      schemaVersion: 1,
      error: {
        code: 'INVALID_OPTIONS',
        message: 'Validity days must be an integer between 1 and 825.',
      },
    });
    expect(result.stderr).toEqual([]);
  });

  it.skipIf(process.platform === 'win32')(
    'refuses a symlinked output path without following it',
    async () => {
      const root = fixture();
      const outputDir = home(root);
      const sentinel = join(root, 'sentinel');
      const cert = join(outputDir, 'localhost.pem');
      writeFileSync(sentinel, 'outside bytes');
      symlinkSync(sentinel, cert);
      const result = output();

      await invoke({ _: ['localhost'], output: outputDir });

      expect(process.exitCode).toBe(1);
      expect(result.stderr[0]).toContain(
        'certkit: CA_UNREADABLE: Refusing a symbolic-link output path:',
      );
      expect(readFileSync(sentinel, 'utf8')).toBe('outside bytes');
    },
  );

  it('refuses an output path that is not a regular file', async () => {
    const outputDir = home(fixture());
    mkdirSync(join(outputDir, 'localhost.pem'));
    const result = output();

    await invoke({ _: ['localhost'], output: outputDir });

    expect(process.exitCode).toBe(1);
    expect(result.stderr[0]).toContain(
      'certkit: CA_UNREADABLE: Output path is not a regular file:',
    );
  });

  it.skipIf(process.platform === 'win32' || process.getuid?.() === 0)(
    'reports an output path that cannot be inspected',
    async () => {
      const outputDir = home(fixture());
      chmodSync(outputDir, 0);
      const result = output();

      try {
        await invoke({ _: ['localhost'], output: outputDir });
      } finally {
        chmodSync(outputDir, 0o700);
      }

      expect(process.exitCode).toBe(1);
      expect(result.stderr[0]).toContain(
        'certkit: CA_UNREADABLE: Cannot inspect output path:',
      );
    },
  );
});
