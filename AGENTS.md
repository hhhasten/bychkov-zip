# AGENTS.md — rules for AI agents

This file is mandatory for any AI agent working on a task from
[`TASKS.md`](TASKS.md). It overrides the agent's habits and the conventions of
other projects.

## How to use

The repository owner gives the agent two files — `AGENTS.md` and `TASKS.md` —
plus a task ID. Ready-to-use prompt:

> Read `AGENTS.md` and `TASKS.md` in the repository root. Complete task
> **T-01**. Work on a separate branch. Follow the contract literally. Push the
> branch and open a pull request into `main`, but do not merge it. Finish with a
> report using the template from `AGENTS.md`.

If the agent cannot open the files or run `cargo`, it must say so immediately
and **must not invent** test results.

## 0. The main rule

**One run — one task.** Do exactly what the selected task says. Do not "improve"
neighbouring code, do not refactor unrelated things, and do not add features
nobody asked for.

If the task looks incomplete or contradictory, stop and ask (section 8) instead
of inventing a contract.

## 1. The project

`bychkov-zip` is a small educational command-line archiver written in Rust.

- Core and CLI: `core/` (crate `bychkov-zip`, binary `byz`).
- GUI: `gui/` — postponed, do not touch.
- The `.byz` format version 1 is frozen. Description: `docs/FORMAT.md`.

Roles:

- **maintainer** — the repository owner. May change anything. Only the
  maintainer reviews and merges pull requests into `main`.
- **task agent** — you. You change only the files allowed by your task, push
  only your own task branch, and open a pull request. You never merge it.

## 2. Commands

Run everything from the `core/` directory. The crate uses Rust 2024 edition, so
a toolchain of 1.85 or newer is required (`rustup update stable`).

```sh
cargo fmt --all
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

All three must succeed before committing. `clippy` is run with `-D warnings`:
a warning is an error.

To check the full release build:

```sh
cargo build --release
```

## 3. File map

| Path | Contents | Who may change it |
|---|---|---|
| `core/src/format.rs` | `.byz` header and metadata | maintainer only |
| `core/src/crypto.rs` | Argon2id, AES-GCM | maintainer only |
| `core/src/archiver/**` | archive creation and extraction | maintainer only |
| `core/src/cli/**` | arguments, password, progress | maintainer only |
| `core/src/huffman/**` | Huffman compression | maintainer only |
| `core/src/entropy.rs`, `input.rs`, `path.rs`, `error.rs`, `main.rs` | infrastructure | maintainer only |
| `core/src/lib.rs` | module list | **one line** `pub mod <name>;` |
| `core/src/<your module>/**` | task code | task agent |
| `core/tests/**` | end-to-end tests | maintainer only |
| `core/Cargo.toml`, `Cargo.lock` | dependencies | maintainer only |
| `docs/**`, `README.md`, `AGENTS.md`, `TASKS.md`, `.github/**` | docs and CI | maintainer only |
| `gui/**` | GUI | nobody |

## 4. Hard prohibitions

A task agent **must not**:

1. Change any file marked "maintainer only".
2. Change `Cargo.toml`, `Cargo.lock`, or add/update dependencies. Only `std`
   and crates already listed in `core/Cargo.toml` are allowed.
3. Change the `.byz` format, the format version, Argon2id parameters, or the
   encryption scheme.
4. Change `AGENTS.md`, `TASKS.md`, `README.md`, or `docs/**` — not even to
   "clarify the task".
5. Change or disable existing tests just to make them pass.
6. Delete, rename, or "optimise" other people's modules.
7. Add CLI commands, flags, or `stdout`/`stderr` output.
8. Commit to or push to `main`, merge or rebase anything into `main`, reset a
   shared branch (including `main`) with `git reset --hard`, merge a pull
   request, or force-push a branch that is not yours. Pushing **your own task
   branch** is allowed: `git push -u origin task/T-01-lz77`. After rebasing your
   own branch you may update it with `git push --force-with-lease`; never use
   plain `--force` and never force-push `main`.
9. Commit `target/`, `*.byz`, passwords, keys, temporary files, or any material
   belonging to the course instructor.
10. Use `unsafe` — the crate root denies it with `#![forbid(unsafe_code)]`.
11. Add `println!`, `dbg!`, or `eprintln!` to library code.
12. Silence lints with `#[allow(...)]` instead of fixing the code.
13. Run commands that delete or overwrite data outside the repository.

If a task genuinely requires a new dependency or a forbidden file, **stop and
explain what is needed and why**. Do not do it yourself.

## 5. The only exception

Every task needs its module wired into the crate. Therefore you may add
**exactly one line** to `core/src/lib.rs`:

```rust
pub mod <module_name>;
```

Nothing else in `lib.rs` may change: not the order, not existing lines, not
comments.

If another task is merged before yours, `core/src/lib.rs` may conflict. Rebase
your branch on the latest `main` and keep both `pub mod` lines: one per task.
Do not delete someone else's line.

## 6. Workflow

1. Get the latest `main` and make sure the working tree is clean:
   `git fetch origin`, `git status`, `git log --oneline -3 origin/main`.
2. Create a branch from `origin/main`:
   `git switch -c task/T-01-lz77 origin/main` (ID and short name come from the
   task).
3. Read the whole task and `docs/FORMAT.md` if the task deals with data.
4. Write the tests first, inside your module (`#[cfg(test)] mod tests`).
5. Implement the code.
6. Run `cargo fmt --all`, `cargo test --all-targets`, and
   `cargo clippy --all-targets -- -D warnings`.
7. Make one or more small commits:
   - `test(<module>): ...`
   - `feat(<module>): ...`
   - `fix(<module>): ...`
8. Push your branch: `git push -u origin task/T-01-lz77`.
9. Open a pull request from your branch into `main`, request a review from the
   maintainer and wait for GitHub CI (`CI / check`) to pass. Do not merge the
   pull request yourself.
10. Send a report using the template in section 10.

If `main` moves while you work, rebase only your own branch:
`git fetch origin`, `git rebase origin/main`, then
`git push --force-with-lease`.

Commits should be atomic: tests separately from implementation when that makes
sense. Do not mix unrelated topics in one commit.

## 7. Definition of Done

A task is done only when:

- [ ] the public API matches the contract in `TASKS.md` (names, types, errors);
- [ ] every test listed in the task is present;
- [ ] error paths and edge cases are covered;
- [ ] `cargo fmt --all` changes nothing (`cargo fmt --all -- --check` is clean);
- [ ] `cargo test --all-targets` passes, including the old tests;
- [ ] `cargo clippy --all-targets -- -D warnings` is clean;
- [ ] GitHub CI (`CI / check`) is green on the pull request;
- [ ] only allowed files were changed;
- [ ] exactly one line was added to `lib.rs`;
- [ ] public functions do not `unwrap()`, `expect()`, or panic on input;
- [ ] the report contains real command output.

## 8. When to stop

Stop immediately and ask a question if:

- the contract in `TASKS.md` allows two different readings;
- a new dependency is needed;
- a forbidden file has to be changed;
- an existing test fails for reasons unrelated to your code;
- the task requires integration with `format.rs`, `archiver/**`, `cli/**`, or
  `huffman/**`;
- a merge conflict touches a file you are not allowed to change;
- it is unclear how to handle an error and the contract does not say;
- `cargo` is unavailable or the build fails for environment reasons.

Question format:

```text
STOP. Task T-XX.
Unclear: ...
Options: A) ... B) ...
I will not do the following without an answer: ...
```

Do not continue until you get an answer.

## 9. Code style

- Rust 2024, `std` only (plus crates already in `Cargo.toml`).
- The crate root has `#![forbid(unsafe_code)]`: any `unsafe` block will not
  compile. Do not try to remove or override that attribute.
- Identifiers, comments and error messages in new code: English. Existing
  maintainer modules keep their Ukrainian comments — do not translate or touch
  them.
- Public functions return `crate::error::Result<T>` and use
  `crate::error::ByzError`, unless the task contract specifies another
  signature (for example `encode -> Vec<Token>` or `crc32 -> u32`).
- Invalid input: `ByzError::BadArgs`. Corrupted data: `ByzError::BadFormat`.
- No panics on untrusted input. `unwrap()` is allowed in tests.
- Comments only where they explain "why", not "what". Do not comment every line.
- Keep functions under roughly 40 lines; split them if longer.
- Do not paste large blocks of code from the internet without understanding them.
- Tests must be deterministic: fixed seed, no `sleep`, no time, no network, no
  random ordering, no dependence on the current directory.
- Test data should be small (a few megabytes at most).

## 10. Report

Finish with exactly this report:

```text
Task: T-01
Branch: task/T-01-lz77
Pull request: <url>
Commits: <hash> <subject>, ...

Changed files:
- core/src/lz77/mod.rs (new)
- core/src/lib.rs (+1 line)

Implemented:
- ...

Tests:
- added N tests
- cargo test --all-targets: N passed, 0 failed
- cargo clippy --all-targets -- -D warnings: ok
- cargo fmt --all -- --check: ok

Deviations from the contract: none / ...
Questions: none / ...
```

If something is not done, say so plainly. An unfinished task is better than a
dishonest "done" that fails the tests.

## 11. Typical mistakes that are not allowed

- "I also fixed `format.rs`" — forbidden.
- "I added `serde` / `bincode` / `clap` for convenience" — forbidden.
- "I rewrote the old tests because they got in the way" — forbidden.
- "The tests fail, but it is not related to my code, so I committed anyway" —
  not allowed; report it and stop.
- "I integrated it into the archiver to make it more useful" — integration is
  not part of the task.
- "I added a CLI flag to check it manually" — forbidden; verify with tests.
- "I copied an algorithm from a library and removed the author" — unacceptable;
  write it yourself or name the source in the report.

## 12. Security

- Never log passwords, keys, or file contents.
- Do not weaken path, size, or format validation.
- Do not add code that writes outside the output directory.
- Do not disable checks for "performance".
- If a task touches cryptography, do not invent your own scheme; the team tasks
  contain no cryptography work.
