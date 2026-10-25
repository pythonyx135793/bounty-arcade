'use strict';
const fs = require('node:fs');
const path = require('node:path');
const output = process.env.ARCADE_OBSERVATION_DIR;
if (!/^\/out\/(base|candidate)$/.test(output || '')) throw Error('Invalid observation directory');
const write = value => fs.appendFileSync(path.join(output, 'steps.jsonl'), JSON.stringify({ at: new Date().toISOString(), ...value }) + '\n');
module.exports = class {
  onBegin(config, suite) {
    write({ kind: 'begin', workers: config.workers, configFile: config.configFile,
      projects: config.projects.map(p => ({ name: p.name, timeout: p.timeout, retries: p.retries, testDir: p.testDir, testMatch: p.testMatch, use: p.use })),
      tests: suite.allTests().map(t => ({ id: t.id, title: t.titlePath(), location: t.location })) });
  }
  onTestBegin(test, result) { write({ kind: 'testBegin', id: test.id, title: test.titlePath(), retry: result.retry, workerIndex: result.workerIndex }); }
  onStepBegin(test, result, step) { write({ kind: 'stepBegin', id: test.id, title: step.title, category: step.category, location: step.location, startTime: step.startTime }); }
  onStepEnd(test, result, step) { write({ kind: 'stepEnd', id: test.id, title: step.title, category: step.category, duration: step.duration, error: step.error }); }
  onTestEnd(test, result) { write({ kind: 'testEnd', id: test.id, status: result.status, duration: result.duration, retry: result.retry, errors: result.errors }); }
  onError(error) { write({ kind: 'runnerError', error }); }
  onEnd(result) { write({ kind: 'end', result }); }
};
