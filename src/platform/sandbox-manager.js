'use strict';

/*
 * src/platform/sandbox-manager.js — isolation backend registry and selection.
 *
 * This build ships only an unverified process backend and a legacy vm backend.
 * Selection is fail-closed: a policy that requires an OS/container/microVM
 * class cannot run untrusted code until a backend passes its verification
 * suite. This prevents "sandbox" claims from exceeding the actual isolation.
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

function defaultManager() {
  const manager = new SandboxManager();
  try {
    const { getLinuxBackend } = require('./os-sandbox');
    const linux = getLinuxBackend();
    if (linux.available()) manager.register(linux);
  } catch { /* optional platform backend */ }
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
