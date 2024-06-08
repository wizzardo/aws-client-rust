#!/usr/bin/env bash
set -e

mkdir -p target

docker buildx build --platform linux/amd64 -t aws-client-rust -f build.dockerfile .
docker create -ti --name dummy aws-client-rust bash
docker cp dummy:/app/target/release/aws-client-rust target/aws-client-rust-x86
docker rm -f dummy

docker buildx build --platform linux/arm64 -t aws-client-rust -f build.dockerfile .
docker create -ti --name dummy aws-client-rust bash
docker cp dummy:/app/target/release/aws-client-rust target/aws-client-rust-arm64
docker rm -f dummy
