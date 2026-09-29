import { spawn } from 'node:child_process';
import { CertkitError } from '../core/errors.js';

export function shQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

export function elevate(argv: string[]): Promise<void> {
  if (process.platform === 'win32')
    return Promise.reject(
      new CertkitError(
        'UNSUPPORTED_PLATFORM',
        'Certkit has no elevated Windows trust-store command.',
      ),
    );
  if (!argv.length || argv.some((part) => typeof part !== 'string'))
    return Promise.reject(
      new CertkitError('INVALID_OPTIONS', 'An elevated command is required.'),
    );

  const command = argv.map(shQuote).join(' ');
  // Only Linux elevates (its system store is root-owned; macOS trust is
  // user-domain and Windows has no elevated trust command). Plain sudo on the
  // inherited terminal: pkexec needs a GUI polkit agent that headless servers
  // and SSH sessions lack; non-TTY sudo fails fast with the manual command.
  if (process.platform !== 'linux')
    return Promise.reject(
      new CertkitError(
        'UNSUPPORTED_PLATFORM',
        `Certkit has no elevated trust-store command on ${process.platform}.`,
      ),
    );

  return new Promise((resolve, reject) => {
    const child = spawn('sudo', argv, { stdio: 'inherit' });
    child.on('error', () =>
      reject(
        new CertkitError(
          'STORE_WRITE_FAILED',
          `sudo is unavailable. Run it manually with sudo: ${command}`,
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
          `The elevated command failed or was cancelled. Run it manually with sudo: ${command}`,
        ),
      );
    });
  });
}
