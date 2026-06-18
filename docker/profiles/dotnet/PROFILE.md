# .NET scanning container

The repository under `./src` is a .NET project (C#, F#, or VB), built with NuGet.

## Runtime

- **.NET SDK 10** — `dotnet`. Covers restore, build, test, and run.
- The NuGet package cache (`/opt/nuget`) and CLI home (`/opt/dotnet-home`) live on an exec-capable path rather than under `HOME`, which is a small noexec mount. Telemetry and the first-run banner are off.

## Operating procedure

### Code scanning preparations

Restore dependencies and build the solution or project:

```bash
cd src
dotnet restore   # or let build/test restore implicitly
dotnet build --no-restore
```

`dotnet` discovers the `.sln` or `.csproj` in the current directory; point it at a specific one if there are several.
If restore fails with a network error the scan is offline — work from the source already present and note which checks
you had to skip.

### Creating reproducers

Every finding ships with a reproducer — a small piece of code that, when run in this container, actually triggers the
issue. Paste the exact command you ran and the verbatim output (error message, return value, observable side effect)
into the finding. Reasoning-only or "this would" reproducers do not count; if you couldn't run it here, say so
explicitly instead of inventing one.

- A focused test: add an xUnit/NUnit/MSTest case to the project's test assembly and run
  `dotnet test --filter 'FullyQualifiedName~Namespace.ClassName.Method'`. The test output is the evidence.
- A standalone program: `dotnet new console -o /tmp/poc`, add a `ProjectReference` or `PackageReference` to the code
  under test, and `dotnet run --project /tmp/poc`.
- Drive the vulnerable method directly with the malicious input (a crafted string, a hostile serialized payload, an XML
  document for an XXE sink) rather than booting the whole application — keeps the reproducer minimal and the evidence
  trivial to verify.

## Out of scope

- Restored packages under the NuGet cache — third-party code, not the target of this scan unless a finding
  specifically pivots through one.
