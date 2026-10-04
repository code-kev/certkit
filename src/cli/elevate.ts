import { spawn } from 'node:child_process';
import { CertkitError } from '../core/errors.js';

export function shQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function elevate(argv: string[]): Promise<void> {
  const executable = argv[0];
  if (!executable || argv.some((part) => typeof part !== 'string'))
    return Promise.reject(
      new CertkitError('INVALID_OPTIONS', 'An elevated command is required.'),
    );
  if (process.platform === 'win32')
    return Promise.reject(
      new CertkitError(
        'UNSUPPORTED_PLATFORM',
        'Certkit has no elevated Windows trust-store command.',
      ),
    );
  const command = argv.map(shQuote).join(' ');
  // Only Linux elevates (its system store is root-owned; macOS trust is
  // user-domain and Windows has no elevated trust command). Root runs
  // directly; other users use plain sudo on the inherited terminal. pkexec
  // needs a GUI polkit agent that headless servers and SSH sessions lack;
  // non-TTY sudo fails fast with the manual command.
  if (process.platform !== 'linux')
    return Promise.reject(
      new CertkitError(
        'UNSUPPORTED_PLATFORM',
        `Certkit has no elevated trust-store command on ${process.platform}.`,
      ),
    );

  const isRoot = process.geteuid?.() === 0;
  const manual = isRoot
    ? `Run it manually: ${command}`
    : `Run it manually with sudo: ${command}`;
  return new Promise((resolve, reject) => {
    const child = spawn(
      isRoot ? executable : 'sudo',
      isRoot ? argv.slice(1) : argv,
      {
        stdio: ['inherit', process.stderr.fd, 'inherit'],
      },
    );
    child.on('error', () =>
      reject(
        new CertkitError(
          'STORE_WRITE_FAILED',
          `${isRoot ? 'The command could not be started.' : 'sudo is unavailable.'} ${manual}`,
        ),
      ),
    );
    child.on('exit', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new CertkitError(
          'STORE_WRITE_FAILED',
          `The elevated command failed or was cancelled. ${manual}`,
        ),
      );
    });
  });
}
