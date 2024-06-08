#!/usr/bin/env bash
set -e

cargo clippy -- \
 -A clippy::needless_return \
 -A clippy::let_and_return \
 "$1"