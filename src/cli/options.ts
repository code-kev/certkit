import type { ArgsDef } from 'citty';
import pc from 'picocolors';
import packageJson from '../../package.json' with { type: 'json' };
import type { StatusReport } from '../index.js';

export interface CliApi {
  caDir(): string;
  status(): Promise<StatusReport>;
}

export let jsonOutput: boolean = false;
let colorOutput: boolean = pc.isColorSupported;
export const cliVersion: string = packageJson.version;

export function validateOptions(
  rawArgs: string[],
  definitions: ArgsDef,
): string | undefined {
  const longOptions = new Map<string, 'boolean' | 'string'>();
  const shortOptions = new Map<string, 'boolean' | 'string'>();
  for (const [name, definition] of Object.entries(definitions)) {
    if (definition.type === 'positional') continue;
    const type =
      definition.type === 'string' || definition.type === 'enum'
        ? 'string'
        : 'boolean';
    longOptions.set(name, type);
    const camel = name.replace(/-([a-z])/g, (_match, letter: string) =>
      letter.toUpperCase(),
    );
    longOptions.set(camel, type);
    const aliasesValue = 'alias' in definition ? definition.alias : undefined;
    const aliases = Array.isArray(aliasesValue)
      ? aliasesValue
      : aliasesValue
        ? [aliasesValue]
        : [];
    for (const alias of aliases) {
      if (alias.length === 1) shortOptions.set(alias, type);
      else longOptions.set(alias, type);
    }
  }

  for (let index = 0; index < rawArgs.length; index++) {
    const arg = rawArgs[index]!;
    if (arg === '--') break;
    if (arg.startsWith('--')) {
      const flag = arg.slice(2).split('=', 1)[0] ?? '';
      const negative = flag.startsWith('no-');
      const type = longOptions.get(negative ? flag.slice(3) : flag);
      if (type === undefined || (negative && type !== 'boolean'))
        return `Unknown option '--${flag}'`;
      if (
        type === 'string' &&
        !arg.includes('=') &&
        rawArgs[index + 1] !== '--'
      )
        index++;
    } else if (arg.startsWith('-') && arg.length > 1) {
      for (let offset = 1; offset < arg.length; offset++) {
        const letter = arg[offset]!;
        const type = shortOptions.get(letter);
        if (type === undefined) return `Unknown option '-${letter}'`;
        if (type === 'string') {
          if (offset === 1 && arg.length === 2 && rawArgs[index + 1] !== '--')
            index++;
          break;
        }
      }
    }
  }
  return undefined;
}

export function setGlobalOptions(options: {
  json?: boolean;
  color?: boolean;
}): void {
  jsonOutput = options.json === true;
  colorOutput = pc.isColorSupported && options.color !== false;
}

export function colors(color?: boolean): ReturnType<typeof pc.createColors> {
  return pc.createColors(colorOutput && color !== false);
}

export function loadApi(): Promise<CliApi> {
  const load = (name: string) => import(name);
  return load('certkit') as Promise<CliApi>;
}
