'use strict';

/*
 * src/platform/metrics.js — dependency-free Prometheus metrics.
 *
 * Service metrics are in-process counters/gauges. They are intentionally
 * simple: Prometheus scrapes a loopback /metrics endpoint; no network or
 * external SDK is involved. Label values must be low-cardinality (route,
 * method, status, decision) — never ticket IDs or principals.
 */

const process = require('process');

function escapeLabel(value) {
  return String(value == null ? '' : value).replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}

function labelKey(labels) {
  if (!labels) return '';
  const keys = Object.keys(labels).sort();
  if (!keys.length) return '';
  return keys.map((k) => `${k}="${escapeLabel(labels[k])}"`).join(',');
}

class MetricsRegistry {
  constructor(opts = {}) {
    this.service = opts.service || 'vibeguard';
    this.version = opts.version || null;
    this.startedAt = Date.now();
    this.counters = new Map();
    this.gauges = new Map();
    this.sums = new Map();
    this.counts = new Map();
  }

  _counter(name, labels) {
    const key = `${name}\0${labelKey(labels)}`;
    if (!this.counters.has(key)) this.counters.set(key, { name, labels: labels || {}, value: 0 });
    return this.counters.get(key);
  }

  inc(name, labels = {}, value = 1) {
    const item = this._counter(name, labels);
    item.value += Number(value) || 0;
    return this;
  }

  set(name, value, labels = {}) {
    const key = `${name}\0${labelKey(labels)}`;
    this.gauges.set(key, { name, labels, value: Number(value) || 0 });
    return this;
  }

  observe(name, seconds, labels = {}) {
    const key = `${name}\0${labelKey(labels)}`;
    const current = this.sums.get(key) || { name, labels, sum: 0, count: 0 };
    current.sum += Number(seconds) || 0;
    current.count += 1;
    this.sums.set(key, current);
    return this;
  }

  snapshot() {
    return {
      service: this.service,
      version: this.version,
      uptimeSeconds: Number(((Date.now() - this.startedAt) / 1000).toFixed(3)),
      counters: [...this.counters.values()].map((x) => ({ name: x.name, labels: x.labels, value: x.value })),
      gauges: [...this.gauges.values()].map((x) => ({ name: x.name, labels: x.labels, value: x.value })),
      summaries: [...this.sums.values()].map((x) => ({ name: x.name, labels: x.labels, sum: x.sum, count: x.count })),
    };
  }

  render() {
    const lines = [];
    const written = new Set();
    const type = (name, kind) => {
      if (written.has(name)) return;
      written.add(name);
      lines.push(`# TYPE ${name} ${kind}`);
    };

    const counters = [...this.counters.values()].sort((a, b) => (a.name + labelKey(a.labels)).localeCompare(b.name + labelKey(b.labels)));
    for (const item of counters) {
      type(item.name, 'counter');
      lines.push(`${item.name}${item.labels && Object.keys(item.labels).length ? `{${labelKey(item.labels)}}` : ''} ${item.value}`);
    }
    const gauges = [...this.gauges.values()].sort((a, b) => (a.name + labelKey(a.labels)).localeCompare(b.name + labelKey(b.labels)));
    for (const item of gauges) {
      type(item.name, 'gauge');
      lines.push(`${item.name}${item.labels && Object.keys(item.labels).length ? `{${labelKey(item.labels)}}` : ''} ${item.value}`);
    }
    for (const item of [...this.sums.values()].sort((a, b) => (a.name + labelKey(a.labels)).localeCompare(b.name + labelKey(b.labels)))) {
      const labels = item.labels && Object.keys(item.labels).length ? `${labelKey(item.labels)}` : '';
      type(item.name, 'summary');
      lines.push(`${item.name}_sum${labels ? `{${labels}}` : ''} ${item.sum.toFixed(6)}`);
      lines.push(`${item.name}_count${labels ? `{${labels}}` : ''} ${item.count}`);
    }

    const mem = process.memoryUsage();
    lines.push('# TYPE vibeguard_process_uptime_seconds gauge');
    lines.push(`vibeguard_process_uptime_seconds ${((Date.now() - this.startedAt) / 1000).toFixed(3)}`);
    lines.push('# TYPE vibeguard_process_resident_memory_bytes gauge');
    lines.push(`vibeguard_process_resident_memory_bytes ${mem.rss}`);
    lines.push('# TYPE vibeguard_process_heap_used_bytes gauge');
    lines.push(`vibeguard_process_heap_used_bytes ${mem.heapUsed}`);
    lines.push('# TYPE vibeguard_build_info gauge');
    lines.push(`vibeguard_build_info{service="${escapeLabel(this.service)}",version="${escapeLabel(this.version || 'unknown')}",node="${escapeLabel(process.versions.node)}"} 1`);
    return lines.join('\n') + '\n';
  }
}

function defaultMetrics(opts = {}) {
  return new MetricsRegistry(opts);
}

module.exports = { MetricsRegistry, defaultMetrics, escapeLabel };
