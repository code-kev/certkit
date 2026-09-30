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
