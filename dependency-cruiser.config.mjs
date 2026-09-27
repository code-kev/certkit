export default {
  forbidden: [
    {
      name: 'core-to-outer-layers',
      severity: 'error',
      from: { path: '^src/core/' },
      to: { path: '^src/(platforms|cli|integrations)/' },
    },
    {
      name: 'platforms-to-cli-or-integrations',
      severity: 'error',
      from: { path: '^src/platforms/' },
      to: { path: '^src/(cli|integrations)/' },
    },
  ],
  options: { doNotFollow: { path: 'node_modules' } },
};
