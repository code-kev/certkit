import { describe, expect, it } from 'vitest';
import { CertkitError } from '../../src/core/errors.js';

describe('CertkitError', () => {
  it('carries a machine-readable code and cause', () => {
    const e = new CertkitError('INVALID_NAME', "bad name: '..'", { cause: 42 });
    expect(e.code).toBe('INVALID_NAME');
    expect(e).toBeInstanceOf(Error);
    expect(e.message).toContain('bad name');
    expect(e.cause).toBe(42);
  });
});
