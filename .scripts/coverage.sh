#!/bin/bash
#
# Produces lcov.info for the whole crate.
#
# Replaces an earlier kcov script that had been a no-op since the crate was
# renamed: it looked for target/debug/oidc-token-test-service*, which has not
# existed since, so the loop body never ran and the upload carried no data.
set -euo pipefail

rustup component add llvm-tools-preview

# Cached in ~/.cargo between runs, so this is a one-off cost per cache key.
if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    cargo install cargo-llvm-cov --locked
fi

cargo llvm-cov --all --locked --lcov --output-path lcov.info
cargo llvm-cov report --summary-only

# Codecov's bash uploader (the previous mechanism) was retired in 2022. To send
# the report, add the codecov orb to .circleci/config.yml and follow this step
# with `codecov/upload: {file: lcov.info}`; the token belongs in a CircleCI
# context, never in the config file.
