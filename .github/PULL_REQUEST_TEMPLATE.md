<!--
Thanks for contributing! Keep this PR small and focused. One change per PR.
If this is a non-trivial change, please link the design issue.
-->

## What this PR does

<!-- 1-3 sentences. What did you change and why? -->

## Linked issue

<!-- Closes #NNN  /  Refs #NNN -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor (no behavior change)
- [ ] Docs only
- [ ] Build / CI

## Validation

- [ ] `make test` passes
- [ ] `golangci-lint run ./...` is clean
- [ ] `cd tui && cargo test && cargo clippy --all-targets -- -D warnings` is clean
- [ ] Tested on a real Linux machine (kernel `_____`) with `sudo make install`
- [ ] BPF verifier accepts the program (no `make generate` errors)

## Reviewer notes

<!--
Anything reviewers should know? Tricky bits, intentional tradeoffs, things
deferred to a follow-up PR?
-->
