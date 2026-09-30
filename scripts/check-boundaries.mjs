import { spawnSync } from 'node:child_process';

const result = spawnSync(
  'pnpm',
  [
    'exec',
    'depcruise',
    'src',
    '--config',
    'dependency-cruiser.config.mjs',
    '--output-type',
    'json',
  ],
  { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
);
if (result.error) throw result.error;
const graph = JSON.parse(result.stdout);
if (!graph.modules.some((module) => module.source.startsWith('src/')))
  throw new Error(
    'Boundary analysis scanned no source modules; check TypeScript/tool compatibility.',
  );
if (result.status !== 0 || graph.summary.error > 0) {
  console.error(graph.summary.violations);
  process.exitCode = 1;
} else {
  console.log(
    `Boundary rules passed: ${graph.summary.totalCruised} modules, ${graph.summary.totalDependenciesCruised} dependencies.`,
  );
}
