# Deserialization review

## Parser versus object construction

Parsing untrusted JSON, YAML, XML, or a compact binary format is not by itself
unsafe deserialization. The security boundary changes when data can select a
runtime type, invoke constructors or hooks, revive executable values, mutate
privileged objects, or trigger gadget behavior during decode.

Identify the decoded target type and the exact loader options. Then trace the
decoded object to a security-sensitive action. A generic claim that a format
can be unsafe is not evidence for this repository.

## High-signal patterns

Investigate native object serialization, unrestricted polymorphic binding,
type-name discriminators, unsafe YAML constructors, object hooks, reflection
decoders, user-controlled class/module names, and application-specific
deserializers that dispatch methods from input.

Also inspect conversions after an otherwise inert parse. A safe data parser can
become dangerous when later code uses decoded fields to select classes,
templates, commands, file paths, or plugins.

## Required validation

- Determine the installed library and version from local source or manifests.
- Read the actual decode configuration and target type.
- Check whether a safe loader, type allowlist, explicit schema, or inert data
  representation is used.
- Prove the reported behavior is currently reachable from untrusted data.

Do not report a parser solely because a historical version or a different
configuration was vulnerable.

## Framework and runtime notes

- Python: SafeLoader-style YAML parsing and json decoding usually produce inert
  data. Investigate custom constructors, object hooks, pickle-like formats,
  and later dispatch based on decoded values.
- Java and JVM libraries: ObjectInputStream, unrestricted polymorphic binding,
  type metadata, and gadget-capable serializers require version and
  configuration review. A typed DTO with a closed mapper is different.
- Ruby and PHP: Marshal, YAML object tags, unserialize-style APIs, and custom
  callbacks can construct objects; verify whether untrusted input can select
  classes or trigger hooks.
- Go: encoding/json and encoding/gob have different constraints. Do not infer
  arbitrary code execution from a decode alone; establish the target type and
  any later action driven by decoded fields.
