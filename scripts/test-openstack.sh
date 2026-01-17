#!/bin/bash
# E2E test with OpenStack provider (CAPO)
#
# Prerequisites:
# - Ubuntu cloud image with cloud-init (check: openstack image list)
# - External network for floating IPs (check: openstack network list --external)
# - Flavors for VMs (check: openstack flavor list)
# - Optional: SSH keypair (check: openstack keypair list)
#
# CAPO will create internal managed subnets automatically.

set -e

# OpenStack authentication
export OS_AUTH_URL=http://localhost:8080/openstack-keystone/v3
export OS_USERNAME=demo
export OS_PASSWORD=P9eUFpvCmn1B
export OS_USER_DOMAIN_NAME=users
export OS_PROJECT_DOMAIN_NAME=users
export OS_PROJECT_NAME=demo
export OS_AUTH_VERSION=3
export OS_IDENTITY_API_VERSION=3

# OpenStack cluster configuration
# Run these to find values:
#   openstack network list --external  -> OS_EXTERNAL_NETWORK
#   openstack image list               -> OS_IMAGE_NAME
#   openstack flavor list              -> OS_CP_FLAVOR, OS_WORKER_FLAVOR
#   openstack keypair list             -> OS_SSH_KEY_NAME
export OS_EXTERNAL_NETWORK="${OS_EXTERNAL_NETWORK:-external-network}"
export OS_IMAGE_NAME="${OS_IMAGE_NAME:-ubuntu}"
export OS_CP_FLAVOR="${OS_CP_FLAVOR:-m1.large}"
export OS_WORKER_FLAVOR="${OS_WORKER_FLAVOR:-m1.large}"
export OS_SSH_KEY_NAME="${OS_SSH_KEY_NAME:-demo}"

export LATTICE_MGMT_PROVIDER=openstack
export LATTICE_WORKLOAD_PROVIDER=openstack
export LATTICE_MGMT_BOOTSTRAP=kubeadm
export LATTICE_WORKLOAD_BOOTSTRAP=rke2

cargo test -p lattice-cli --features provider-e2e --test e2e pivot_e2e -- --nocapture
