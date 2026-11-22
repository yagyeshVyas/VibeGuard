'use strict';

/*
 * Labeled detection corpus runner.
 *   node test/corpus/run.js [--json] [--gate]
 *
 * The corpus is deliberately small and local; it is a regression baseline, not
 * a statistically representative benchmark. It reports precision/recall/FPR/
 * FNR for the prompt and tool-poisoning detectors actually used by VibeGuard.
 */

const fs = require('fs');
const path = require('path');
const { inspectPrompt } = require('../../src/firewall');
const { createEngine } = require('../../src/mcp-firewall');

const samples = JSON.parse(fs.readFileSync(path.join(__dirname, 'samples.json'), 'utf8'));
const json = process.argv.includes('--json');
const gate = process.argv.includes('--gate');

function metrics(rows) {
  let tp = 0; let fp = 0; let tn = 0; let fn = 0;
  for (const r of rows) {
    if (r.label === 'attack' && r.detected) tp++;
    else if (r.label === 'attack') fn++;
    else if (r.detected) fp++;
    else tn++;
  }
  const precision = tp + fp ? tp / (tp + fp) : 0;
  const recall = tp + fn ? tp / (tp + fn) : 0;
  const fpr = fp + tn ? fp / (fp + tn) : 0;
  const fnr = fn + tp ? fn / (fn + tp) : 0;
  const accuracy = (tp + tn) / Math.max(1, rows.length);
  return { tp, fp, tn, fn, precision: Number(precision.toFixed(4)), recall: Number(recall.toFixed(4)), fpr: Number(fpr.toFixed(4)), fnr: Number(fnr.toFixed(4)), accuracy: Number(accuracy.toFixed(4)) };
}

const promptRows = samples.prompts.map((s) => ({
  id: s.id,
  label: s.label,
  detector: 'prompt',
  detected: inspectPrompt(s.text).action === 'block',
  text: s.text,
}));

const engine = createEngine({ root: process.cwd(), policy: {}, logger: { log() {} } });
const toolRows = samples.tools.map((s) => {
  const inspected = engine.inspectToolList('corpus', [{ name: s.id, description: s.description, inputSchema: {} }]);
  return { id: s.id, label: s.label, detector: 'tool', detected: inspected.removed.length > 0, text: s.description };
});

const result = {
  corpus: path.join(__dirname, 'samples.json'),
  prompt: metrics(promptRows),
  tool: metrics(toolRows),
  misses: [...promptRows, ...toolRows].filter((r) => r.label === 'attack' && !r.detected).map((r) => ({ id: r.id, detector: r.detector })),
  falsePositives: [...promptRows, ...toolRows].filter((r) => r.label === 'benign' && r.detected).map((r) => ({ id: r.id, detector: r.detector })),
};

if (json) console.log(JSON.stringify(result, null, 2));
else {
  console.log(`Prompt detector: precision=${result.prompt.precision} recall=${result.prompt.recall} FPR=${result.prompt.fpr} FNR=${result.prompt.fnr}`);
  console.log(`Tool detector:   precision=${result.tool.precision} recall=${result.tool.recall} FPR=${result.tool.fpr} FNR=${result.tool.fnr}`);
  console.log(`Misses: ${result.misses.map((m) => m.id).join(', ') || 'none'}`);
  console.log(`False positives: ${result.falsePositives.map((m) => m.id).join(', ') || 'none'}`);
}

if (gate) {
  const minPrecision = 0.8;
  const minRecall = 0.7;
  if (result.prompt.precision < minPrecision || result.prompt.recall < minRecall || result.tool.precision < minPrecision || result.tool.recall < minRecall) {
    console.error('Corpus gate failed: precision/recall below configured thresholds');
    process.exitCode = 1;
  }
}
