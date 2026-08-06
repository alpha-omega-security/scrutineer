# Ownership and lifetime

Memory lifetime bugs usually cross functions. Build an ownership map rather
than judging a `free` or dereference in isolation.

The primary targets are use-after-free, double-free, invalid-free, stale
borrows, and reentrancy that invalidates state still used by an outer frame.

## Ownership map

For each candidate object, identify:

- creator and initial owner;
- borrowed and owning aliases;
- ownership-transfer calls and their success/failure rules;
- callbacks, queues, threads, foreign runtimes, and caches retaining aliases;
- invalidation points: free, resize, move, container growth, reset, close, and
  teardown;
- cleanup on every early return, retry, cancellation, and partial-init path.

Read reference-count operations and their atomicity. Confirm whether weak,
borrowed, and callback references are upgraded or pinned before use.

## High-value patterns

- A cleanup label releases an object already released in an earlier branch.
- Partial initialization leaves a field appearing owned when initialization
  failed, or cleanup assumes a field was initialized.
- A callback can synchronously or asynchronously free, resize, detach, or
  replace the object whose method invoked it.
- Reentrancy invalidates iterator or parser state that the outer frame resumes.
- A queued task, timer, signal handler, or foreign runtime outlives a borrowed
  pointer or stack allocation.
- One API documents borrowed input while another layer treats it as owned, or
  ownership is transferred only on success but cleanup ignores the result.
- A C++ move/destructor path or exception unwind releases the same resource
  through two owners.

## False-positive controls

Do not report from lexical order alone. Resolve callback synchronicity,
reference pinning, lock scope, object state, all return values, and cleanup
macros. A pointer comparison, nulling assignment, or retained owner may make a
suspicious path safe; conversely, nulling one alias does not invalidate others.
