# Contributing

- Read the rules in `README.md`: one crate, one job; a crate is at most 3,000 lines and no file over
  1,200; default features stay light.
- Before a pull request run `scripts/gates.sh` (tests, the line ratchet, the dependency-weight check).
- Budgets in `budget/` may only fall. A change that raises one needs a written reason in the crate's README.
- A bug fix comes with a test that fails without it.
