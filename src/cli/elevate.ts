import { exec } from '@expo/sudo-prompt';
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
  return new Promise((resolve, reject) => {
    exec(command, { name: 'Certkit' }, (error) => {
      if (!error) {
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
