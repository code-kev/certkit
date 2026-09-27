export type ErrorCode =
  | 'INVALID_NAME'
  | 'NAME_LIMIT'
  | 'INVALID_OPTIONS'
  | 'UNSUPPORTED_PLATFORM'
  | 'CA_UNREADABLE'
  | 'GENERATION_FAILED'
  | 'STORE_WRITE_FAILED';

export class CertkitError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string, opts?: { cause?: unknown }) {
    super(message, opts);
    this.name = 'CertkitError';
    this.code = code;
  }
}
