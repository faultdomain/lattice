#!/bin/bash
# E2E test with Docker provider (CAPD)
# No external dependencies - runs entirely in kind clusters

set -e

LATTICE_MGMT_PROVIDER=docker \
LATTICE_WORKLOAD_PROVIDER=docker \
LATTICE_MGMT_BOOTSTRAP=kubeadm \
LATTICE_WORKLOAD_BOOTSTRAP=rke2 \
cargo test -p lattice-cli --features provider-e2e --test e2e pivot_e2e -- --nocapture
