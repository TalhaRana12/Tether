const { defineConfig, devices } = require('@playwright/test');

// Tier: these are workflow §5 **integration** tests — exactly one real dependency, a
// browser. They are not unit tests (a browser is a dependency) and not acceptance tests
// (no control plane, no database, no agent).
module.exports = defineConfig({
  testDir: './tests',
  fullyParallel: true,
  // A test that only passes on a retry is a flaky test, and a flaky security test is
  // worse than none — it teaches people to re-run until green.
  retries: 0,
  forbidOnly: true,
  reporter: [['list']],

  use: {
    baseURL: `http://localhost:${process.env.PORT || 4173}`,
    trace: 'retain-on-failure',
  },

  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],

  webServer: {
    command: 'node server.js',
    url: `http://localhost:${process.env.PORT || 4173}/audit-keygen.html`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
