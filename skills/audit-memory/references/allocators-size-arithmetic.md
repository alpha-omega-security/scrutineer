# Allocators and size arithmetic

Allocator names do not define their contracts. Read every local allocation and
resize wrapper before evaluating its callers. Treat allocator wrappers as
first-class inventory entries rather than hiding their primitive operations.

## Wrapper inventory

For each wrapper, record:

- accepted type and unit for count, size, alignment, and capacity;
- whether addition and multiplication are checked before allocation;
- maximum object limits and whether they apply before or after conversion;
- behavior for zero-size requests, out-of-memory, and invalid alignment;
- whether failure preserves, frees, or replaces the original allocation;
- whether returned storage is initialized and who owns release;
- whether callback-provided allocators use the same contract as defaults.

Do not assume a function named `xrealloc` aborts on failure, or that a function
named `reallocarray` has platform-library semantics. Follow its definition.

## realloc review

- With standard `realloc`, success can move storage and invalidate all aliases;
  failure preserves the original allocation. A local wrapper may differ.
- Assigning directly back to the sole pointer can lose the original allocation
  on failure. That alone is usually a leak; prove a security impact before
  reporting it.
- Zero-size behavior is contract- and language-version-sensitive. Treat it as
  a separate branch and never infer portability from one platform.
- After growth, update all related pointer, capacity, length, end, and slice
  fields consistently. Look for aliases retained across callbacks or moves.

## Arithmetic checklist

For each allocation and access, write the formula in source types:

    elements * element_size + header + terminator

Then verify:

- every operation is checked before it executes;
- promotion occurs to a sufficiently wide unsigned type before arithmetic;
- negative signed values cannot become large unsigned values;
- narrowing casts occur only after a proven bound;
- rounding and alignment additions cannot overflow;
- encoded, decoded, compressed, and decompressed lengths are not mixed;
- the allocation formula covers the maximum later offset plus access width.

Checking only `len <= max` is insufficient when `len + 1`, `len * stride`, or
alignment rounding is what reaches the allocator.
