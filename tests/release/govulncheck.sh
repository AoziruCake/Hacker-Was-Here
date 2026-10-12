#!/bin/sh
# Networked helper: records the Q11 vulnerability check for the release candidate.
set -eu
test -d /src
mkdir -p /results
cd /src
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./... | tee /results/govulncheck.txt
