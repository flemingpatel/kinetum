# Contributing to Kinetum

## Reports and proposals

Use [GitHub Issues](https://github.com/flemingpatel/kinetum/issues) for bug
reports and proposals. For a bug, include the version or commit, reproduction
steps, expected and observed behavior, and relevant logs. Include the host,
compiler and I/O configuration when they affect the result.

Discuss substantial changes to runtime behavior, ownership, ABIs or provider
contracts before implementation. Describe the problem, proposed approach and
tradeoffs. Small, focused fixes can go directly to a pull request.

## Preparing a change

Follow the existing guides:

- [Platform Engineering Guide](docs/PLATFORM_ENGINEERING_GUIDE.md): design and
  ownership requirements.
- [Coding Guidelines](docs/CODING_GUIDELINES.md): code, comments and tests.
- [Getting Started](docs/GETTING_STARTED.md#1-build): build and test commands.
- [Documentation Guide](docs/DOCUMENTATION_GUIDE.md): documentation checks.

Keep the change focused. Update affected tests, comments and documentation
together. For performance claims, include the tested hardware, workload,
configuration and reproducible comparison, following the engineering guide's
[profiling requirements](docs/PLATFORM_ENGINEERING_GUIDE.md#pat-16-profiling-and-regression-discipline).

## Pull requests

Create a topic branch from `develop` in your fork. Target this repository's
`develop` branch with the pull request. `main` carries releases.

Explain the problem, resulting behavior and any material tradeoffs. Report the
checks you ran and their outcomes, including checks you could not run and any
hardware or architecture limitations. A skipped check is not a pass.
