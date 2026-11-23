'use strict';

/*
 * src/platform/sandbox-manager.js — isolation backend registry and selection.
 *
 * Selection is fail-closed: a policy that requires an OS/container/microVM
 * class cannot run untrusted code until a backend has current, host-specific
 * verification evidence. `verified` is never inferred from the presence of a
 * binary; it comes from the backend's verification suite and a short-lived
 * cache keyed by host identity and suite version.
 */

const { ERROR_CODES, ISOLATION, VibeGuardError } = require('./contracts');

const RANK = {
  [ISOLATION.NONE]: 0,
  [ISOLATION.PROCESS]: 1,
  [ISOLATION.OS]: 2,
  [ISOLATION.CONTAINER]: 3,
  [ISOLATION.MICROVM]: 4,
  [ISOLATION.HARDWARE_VM]: 5,
};

class SandboxManager {
  constructor() {
    this.backends = new Map();
  }

  register(backend) {
    if (!backend || !backend.id) throw new Error('sandbox backend needs an id');
    if (!Object.prototype.hasOwnProperty.call(RANK, backend.isolationClass)) {
      throw new Error(`unknown isolation class: ${backend.isolationClass}`);
    }
    this.backends.set(backend.id, backend);
    return this;
  }

  list() {
    return [...this.backends.values()].map((b) => ({
      id: b.id,
      isolationClass: b.isolationClass,
      verified: b.verified === true,
      verification: b.verification || 'unverified',
      verifiedAt: b.verifiedAt || null,
      evidence: Array.isArray(b.evidence) ? b.evidence : [],
      limitations: b.limitations || [],
    }));
  }

  select(requestedClass = ISOLATION.CONTAINER, opts = {}) {
    const required = RANK[requestedClass];
    if (required === undefined) throw new VibeGuardError(ERROR_CODES.SANDBOX_UNAVAILABLE, `unknown isolation class ${requestedClass}`);
    const candidates = [...this.backends.values()].filter((b) => {
      if (RANK[b.isolationClass] < required) return false;
      return opts.allowUnverified === true || b.verified === true;
    });
    candidates.sort((a, b) => RANK[b.isolationClass] - RANK[a.isolationClass]);
    if (!candidates.length) {
      throw new VibeGuardError(
        ERROR_CODES.SANDBOX_UNAVAILABLE,
        opts.allowUnverified
          ? `no backend provides ${requestedClass}`
          : `no VERIFIED backend provides ${requestedClass}; refusing to claim isolation`,
        { status: 503 }
      );
    }
    return candidates[0];
  }
}

function defaultManager(opts = {}) {
  const manager = new SandboxManager();
  try {
    const { getLinuxBackend } = require('./os-sandbox');
    const linux = getLinuxBackend(opts);
    if (linux.available()) manager.register(linux);
  } catch { /* optional platform backend */ }
  if (process.platform === 'win32') {
    try {
      const { WindowsAppContainerSandbox } = require('./windows-appcontainer');
      const win = new WindowsAppContainerSandbox(opts);
      if (win.available()) manager.register(win);
    } catch { /* optional platform backend */ }
  }
  if (process.platform === 'darwin') {
    try {
      const { MacVMSandbox } = require('./macos-vm');
      const mac = new MacVMSandbox(opts);
      if (mac.available()) manager.register(mac);
    } catch { /* optional platform backend */ }
  }
  manager.register({
    id: 'process',
    isolationClass: ISOLATION.PROCESS,
    verified: false,
    verification: 'unverified',
    limitations: ['same OS user', 'Node permission model is not a kernel sandbox', 'network is not blocked at the OS layer'],
  });
  manager.register({
    id: 'legacy-vm',
    isolationClass: ISOLATION.NONE,
    verified: false,
    verification: 'unverified',
    limitations: ['compatibility runner only', 'host-realm escape was the original audit finding', 'not for untrusted code'],
  });
  return manager;
}

module.exports = { SandboxManager, defaultManager, RANK };
