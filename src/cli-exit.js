'use strict';

/*
 * src/cli-exit.js — how a one-shot VibeGuard command leaves the process.
 *
 * `process.exit()` terminates immediately, even with libuv writes still queued.
 * Redirected to a file that is invisible (the fd accepts writes synchronously),
 * but a piped stdout is non-blocking: writes past the pipe buffer (~64 KiB on
 * Linux/macOS) are still in libuv's queue when the process dies, so the tail of
 * the report is dropped and `--json` arrives as an unterminated string — while
 * the exit code still reports what the scan found. `vibeguard scan . --json |
 * jq` was silently broken for any report bigger than 64 KiB, which is exactly
 * what a real repository produces.
 *
 * `exitWhenFlushed(code)` sets the exit code, queues a zero-length write on
 * stdout/stderr and exits only when that callback fires — i.e. once every chunk
 * queued before it has been handed to the OS. It still hard-exits afterwards,
 * so a command that leaves a timer, socket or child handle behind cannot hang
 * the caller the way a bare `process.exitCode = code` would.
 *
 * Long-running processes (mcp-server, watch mode, the guard daemon, the
 * llm-proxy) keep owning their own lifetime; they call this only on shutdown.
 */

const FLUSH_TIMEOUT_MS = 5000;

function noop() {}

/*
 * A closed reader (`vibeguard scan --json | head -5`) surfaces EPIPE as an
 * unhandled 'error' event, which prints a stack trace over an otherwise clean
 * exit. Swallow stream errors while the last flush is in flight.
 */
function quietStreamErrors(stream) {
  if (!stream || typeof stream.on !== 'function') return;
  try {
    if (stream.listenerCount('error') === 0) stream.on('error', noop);
  } catch {
    /* not a real stream — flushStream skips it */
  }
}

/*
 * Resolves once every write queued on `stream` so far has reached the OS.
 * Never rejects: an exit path must always make progress.
 */
function flushStream(stream) {
  return new Promise((resolve) => {
    if (!stream || stream.destroyed || stream.writableEnded || typeof stream.write !== 'function') {
      resolve();
      return;
    }
    let settled = false;
    let timer = null;
    const finish = () => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      resolve();
    };
    // A destroyed pipe or a reader that stopped consuming must not freeze the
    // exit. Unref'd, so when nothing else holds the loop the process can still
    // end naturally with the exit code that was already set.
    timer = setTimeout(finish, FLUSH_TIMEOUT_MS);
    if (timer && typeof timer.unref === 'function') timer.unref();
    try {
      // The callback for this zero-length write runs only after everything
      // queued before it has been written out.
      stream.write('', finish);
    } catch {
      finish();
    }
  });
}

function flushStdio() {
  quietStreamErrors(process.stdout);
  quietStreamErrors(process.stderr);
  return Promise.all([flushStream(process.stdout), flushStream(process.stderr)]);
}

let inFlightFlush = null;

/*
 * Terminate with `code` once stdout/stderr are drained. The returned promise
 * makes `await` optional — the process exits either way.
 */
async function exitWhenFlushed(code) {
  const final = typeof code === 'number' && Number.isFinite(code) ? code : 0;
  process.exitCode = final; // right code even if a natural exit wins the race
  if (!inFlightFlush) inFlightFlush = flushStdio();
  await inFlightFlush;
  process.exit(final);
}

module.exports = { flushStream, flushStdio, exitWhenFlushed };
