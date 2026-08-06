# C and C++ memory operations

Use this note after identifying the repository's own wrappers and supported
language mode. Local wrapper contracts and build flags take precedence.

## Allocation and containers

- For `malloc(n * sizeof(T))` and equivalent `new[]` counts, prove the
  multiplication cannot wrap before allocation. A later bounds check cannot
  restore the lost high bits.
- `calloc(count, size)` is intended for arrays, but review the implementation
  and platform contract before assuming multiplication overflow is rejected.
- In C++, distinguish object count, byte extent, `size()`, and `capacity()`.
  Growth can invalidate pointers, references, and iterators into `vector`,
  `string`, and project containers.
- Flexible array members, trailing storage, placement new, custom allocators,
  and small-buffer optimization require the concrete object layout, alignment,
  and destruction path to be traced.

## Copy and string operations

- `memcpy` requires valid, non-overlapping source and destination ranges;
  `memmove` supports overlap but still requires both extents to be valid.
- `strncpy` can leave a destination unterminated. Report only when the actual
  source can fill the bound and later code reads it as a terminated string.
- `snprintf` returns the number of characters that would have been written,
  excluding the terminator. Safe truncation checks account for negative
  returns and require the converted return value to be smaller than capacity.
- `sizeof(pointer)` is not the pointed-to allocation size. Check macro and
  template expansion before deciding what expression a size operator sees.
- For `read`, `recv`, `fread`, and decoder callbacks, compare the requested
  count and every later terminator write with the current writable capacity.

## Questions for each hit

1. What exact object or allocation contains the range?
2. In what units are its offset, length, and capacity?
3. Can arithmetic or conversion change those values before the operation?
4. Can growth, move, callback, or error cleanup invalidate an alias?
5. Which supported build product and trust boundary reaches the hit?
