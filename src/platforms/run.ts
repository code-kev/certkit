import { execFile as execFileCallback } from 'node:child_process';
import { constants } from 'node:fs';
import { access } from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';
import { CertkitError } from '../core/errors.js';

const execFile = promisify(execFileCallback);
const privateKey =
  /-----BEGIN [^\r\n]*PRIVATE KEY-----[\s\S]*?-----END [^\r\n]*PRIVATE KEY-----/g;
const redact = (value: string): string =>
  value.replace(privateKey, '[REDACTED]');

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export async function run(
  argv: string[],
  opts?: { timeoutMs?: number },
): Promise<RunResult> {
  if (!argv.length || !argv[0])
    throw new CertkitError('INVALID_OPTIONS', 'A command is required.');

  const controller = new AbortController();
  const timeout = opts?.timeoutMs;
  const timer =
    timeout === undefined
      ? undefined
      : setTimeout(() => controller.abort(), timeout);
  try {
    const { stdout, stderr } = await execFile(argv[0], argv.slice(1), {
      encoding: 'utf8',
      windowsHide: true,
      signal: controller.signal,
    });
    return { code: 0, stdout: redact(stdout), stderr: redact(stderr) };
  } catch (error) {
    const failure = error as NodeJS.ErrnoException & {
      stdout?: string;
      stderr?: string;
      code?: string | number;
    };
    if (controller.signal.aborted)
      throw new Error(`Command timed out after ${timeout} ms: ${argv[0]}`, {
        cause: error,
      });
    if (failure.code === 'ENOENT')
      throw new CertkitError(
        'UNSUPPORTED_PLATFORM',
        `Command not found: ${argv[0]}`,
        {
          cause: error,
        },
      );
    if (typeof failure.code === 'number')
      return {
        code: failure.code,
        stdout: redact(failure.stdout ?? ''),
        stderr: redact(failure.stderr ?? ''),
      };
    throw error;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function resolveNssCertutil(env?: {
  CERTKIT_CERTUTIL?: string;
}): Promise<string | null> {
  if (env?.CERTKIT_CERTUTIL) {
    if (
      path.win32
        .normalize(env.CERTKIT_CERTUTIL)
        .toLowerCase()
        .endsWith('\\windows\\system32\\certutil.exe')
    )
      return null;
    return env.CERTKIT_CERTUTIL;
  }

  const candidates =
    process.platform === 'win32'
      ? [
          path.join(
            process.env['ProgramFiles'] ?? 'C:\\Program Files',
            'Mozilla NSS',
            'certutil.exe',
          ),
          path.join(
            process.env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)',
            'Mozilla NSS',
            'certutil.exe',
          ),
        ]
      : process.platform === 'darwin'
        ? ['/opt/homebrew/bin/certutil', '/usr/local/bin/certutil']
        : ['/usr/bin/certutil', '/usr/local/bin/certutil'];

  for (const candidate of candidates) {
    try {
      await access(candidate, constants.F_OK);
      return candidate;
    } catch {
      // Try the next known NSS location.
    }
  }
  return null;
}
