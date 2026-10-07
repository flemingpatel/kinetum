# Workspace Ownership and Command Authority

These instructions apply to coding agents working in this repository.

- Edit only the repository checkout designated for the task. Other checkouts
  and directories are read-only unless the owner explicitly authorizes changes.
- Do not synchronize, merge, copy, move, or restore other checkouts without
  explicit authorization. Permission to compare checkouts is read-only.
- If the target checkout or intended baseline is ambiguous, report the
  discrepancy and stop before editing.
- Agents may run non-destructive, workspace-local inspection commands without
  renewed permission. This includes `rg`, `sed`, `awk`, `find`, `file`, `wc`,
  read-only Git commands (`status`, `diff`, `show`, `log`, and `ls-files`),
  non-rewriting static-analysis checks, and analysis whose generated output is
  confined to a temporary directory. These commands must not alter the source
  tree, Git index, Git metadata, running processes, remote systems, or external
  state.
- Source edits remain owner-authorized task work within the designated
  checkout. Commands that build, run tests, rewrite formatting, install,
  package, deploy, contact or mutate a remote system, manage processes, alter
  Git state, or write outside that checkout and temporary storage require
  explicit delegation for that task. If a command's effects are uncertain,
  stop and ask.
- Never run destructive or history-changing Git operations, including `reset`,
  `checkout`, `restore`, `clean`, `stash`, `merge`, `rebase`, or `cherry-pick`.
  The general permission for inspection never authorizes these operations.

# Design Checkpoint Discipline

These rules apply to core redesign checkpoints.

- Before editing a checkpoint, re-read this file, the approved design,
  the [Platform Engineering Guide](docs/PLATFORM_ENGINEERING_GUIDE.md), and
  the [Coding Guidelines](docs/CODING_GUIDELINES.md). After context compaction,
  do this again before taking any action.
- Present the exact checkpoint scope, affected-file categories, and the
  permanent-versus-temporary contract decisions to the repository owner. Wait
  for explicit approval before editing.
- Distinguish a temporary capability fence from a permanent interface
  replacement. Temporary unavailability never makes a stable interface,
  command, example, help entry, document section, or diagram obsolete.
- Apply this final-state test before changing any interface or documentation:
  "Will the accepted final design still need this unchanged?" If yes, preserve
  it and implement only the checkpoint's required fail-closed gate. If no,
  replace it once, in the checkpoint that owns the final contract.
- Do not create change-now/change-later churn. Do not remove, rename, rewrite,
  deprecate, or label stable surfaces "for later" merely because an
  intermediate checkpoint cannot execute them.
- Preserve mature source comments, examples, help text, documentation
  structure, tables of contents, and diagrams whenever their final contract
  remains valid. Rewrite them only when the implemented final truth changes;
  preserve their technical depth and update every affected diagram in place.
- Do not add speculative compatibility, legacy, fallback, dual-reader, or
  dormant execution paths. A permanent schema or interface break updates all
  owned consumers atomically and leaves one source of truth.
- If checkpoint scope, final ownership, or future reuse is uncertain, stop and
  ask. Do not infer a broader cleanup or documentation rewrite.

# Reassessment After Rejection or Repeated Mistakes

- Answer the question asked, using its stated assumptions and requested level
  of detail. Provide the requested format and explain where examples and inputs
  come from. Do not turn a narrow question into an unrelated proposal.
- Act on the first substantive correction. After rejection, stop the disputed
  approach and reassess the whole recommendation before proposing another.
  Check all supporting arguments without making the owner refute each one;
  do not reintroduce a rejected approach under another name.
- Before recommending or revising an approach, read the complete affected
  workflow and applicable design, PEG, and policy. Identify the intended
  guarantee, its actual scope, the owner's use case, and any assumptions.
  An existing rule, implementation, or prior approval does not by itself
  establish that a design is correct.
- Research the issue on the web using relevant upstream source code, official
  documentation, and primary research. Choose comparable projects by their
  architecture, workload, ownership, and trust boundaries. Explain why the
  comparison applies; a familiar project name is not supporting evidence.
- Separate verified facts from inference and requirements from implementation
  costs. Compare established alternatives against the same actual use case for
  correctness, security, performance, usability, and maintenance. Explain why
  the evidence favors the recommendation; facts shared by both options do not.
  Prefer the smallest coherent solution that meets the requirement.
- If the policy itself is wrong or applied outside its purpose, identify the
  exact rule, explain the conflict with evidence, and propose its precise
  correction. Do not defend it merely because it exists, silently bypass it,
  or add machinery to make the mismatch disappear. Present the rationale
  before further implementation, following the existing checkpoint approval
  rules and retaining authorization already granted for routine fixes.
- Preserve decisions and authorization across interruptions. Keep discussion
  separate from permission to edit; do not seek approval again for work already
  authorized. Ask only about consequential gaps unresolved by available context
  and code.

# Final Closure Validation Discipline

These rules apply before handing any foundational checkpoint to the repository
owner for its build and execution gate.

- Treat closure validation as one systematic whole-patch audit, not a sequence
  of narrow reactive passes. For every changed invariant, trace its sole
  authority, every producer, every direct and indirect consumer, every manual
  test fixture, and every documentation or packaging projection it affects.
- Audit the complete state-product: construction, normal success, rejection
  before mutation, partial progress, retry, cancellation, timeout, shutdown,
  reverse-order teardown, and destruction. Every linear resource must have one
  exact fate on every edge.
- A new required precondition triggers a complete call-site inventory. Tests
  are clients of the production contract and receive no test-only shortcut;
  manually composed fixtures must establish the same prerequisites and cleanup
  ownership as production.
- Re-derive inherited concurrency and ordering assumptions whenever scheduling,
  publication, ownership transfer, or thread placement changes. Do not carry a
  formerly valid invariant forward mechanically into a new concurrency model.
- Review failure diagnostics together with cleanup. A failed assertion or
  early return must not obscure the original defect by later terminating on
  unrelated live fixture ownership; intentional fail-stop tests must prove the
  intended invariant rather than an earlier destructor.
- Include hot-path shape, cache-line and NUMA ownership, bounded-work
  arithmetic, ABI/layout, generated-code behavior, compiler diagnostics, and
  architecture-specific build/link/assembly obligations in the impact audit.
  Algorithmic review alone is not closure evidence.
- Distinguish what static reasoning can establish from what only execution can
  establish. Native and target-host gates confirm runtime, toolchain, timing,
  and architecture behavior; they should not be the first mechanism used to find a
  statically derivable missing caller, ownership edge, or fixture prerequisite.
- When one defect is found, audit the complete defect class across the patch
  before handing it back. Correct all in-scope siblings together, while adding
  no speculative cleanup, compatibility path, test-count churn, or pending-gate
  documentation noise.
