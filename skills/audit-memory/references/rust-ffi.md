# Unsafe Rust and FFI

Safe Rust is out of scope unless an unsafe implementation or foreign boundary
breaks the abstraction it relies on. Audit every unsafe block and extern
boundary in first-party code that handles untrusted data.

## Raw pointers and slices

- `slice::from_raw_parts` requires a non-null, aligned pointer, one allocation,
  initialized elements, a representable total size, and a lifetime during
  which the memory remains valid and is not mutated contrary to alias rules.
- `from_raw_parts_mut` additionally requires unique mutable access for the
  produced lifetime.
- Pointer `add` and `offset`, raw indexing, `copy_nonoverlapping`, `copy`, and
  `write_bytes` require the complete range to remain within valid storage.
- `CStr::from_ptr` requires a readable NUL-terminated sequence and a valid
  lifetime. Resolve where the terminator and maximum readable extent come from.

## Vec and allocation ownership

- `Vec::set_len` requires the new length not to exceed capacity and every newly
  exposed element to be initialized.
- `Vec::from_raw_parts` requires matching pointer, length, capacity, alignment,
  allocation layout, and allocator ownership. A foreign allocation is not
  automatically compatible with Rust's global allocator.
- `ManuallyDrop`, `mem::forget`, raw ownership transfer, and custom Drop code
  need one clear final owner on every success and error path.
- Container growth can invalidate pointers handed to C or stored across an FFI
  call even when Rust references are not visible in the source.

## FFI contract

Trace both sides of every boundary:

- ABI, struct layout, packing, alignment, integer widths, signedness, and enum
  representation;
- pointer nullability, buffer length units, initialization, mutability, and
  lifetime;
- who allocates and who frees, with which allocator and layout;
- whether callbacks retain pointers or can re-enter and invalidate state;
- panic/exception/unwind behavior across the boundary;
- pinning and movement of runtime-managed strings, arrays, and objects.

Comments are not enough when the implementation violates them, but an unsafe
operation is not a finding when every precondition is established by all
reachable callers. State the exact missing precondition and attacker-controlled
value in any report.
