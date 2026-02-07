#!/usr/bin/env bash
#
# Setup AWS account for Cluster API Provider AWS (CAPA)
#
# This script uses clusterawsadm to bootstrap IAM resources and encode credentials.
#
# Prerequisites:
#   - AWS CLI configured with appropriate credentials
#   - clusterawsadm installed (https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases)
#
# Usage:
#   ./setup-aws-capi.sh [options]
#
# Options:
#   --region REGION       AWS region (default: us-west-2)
#   --config FILE         Custom clusterawsadm config file
#   --enable-eks          Enable EKS support
#   --dry-run             Print commands without executing

set -euo pipefail

# Defaults
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-west-2}}"
CONFIG_FILE=""
ENABLE_EKS=false
DRY_RUN=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --region) REGION="$2"; shift 2 ;;
        --config) CONFIG_FILE="$2"; shift 2 ;;
        --enable-eks) ENABLE_EKS=true; shift ;;
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help)
            head -18 "$0" | tail -16
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Check for clusterawsadm
if ! command -v clusterawsadm &> /dev/null; then
    echo "Error: clusterawsadm not found"
    echo ""
    echo "Install it from: https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases"
    echo ""
    echo "Example (macOS):"
    echo "curl -L https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases/latest/download/clusterawsadm-darwin-amd64 -o clusterawsadm"
    echo "chmod +x clusterawsadm"
    echo "sudo mv clusterawsadm /usr/local/bin/"
    exit 1
fi

run() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] $*"
    else
        echo ">> $*"
        "$@"
    fi
}

echo "=== CAPA AWS Setup (using clusterawsadm) ==="
echo "Region: $REGION"
echo ""

# Set AWS region
export AWS_REGION="$REGION"

# Get AWS account info
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "AWS Account: $ACCOUNT_ID"
echo ""

#
# 1. Bootstrap IAM resources via CloudFormation
#
echo "=== Bootstrapping IAM Resources ==="

BOOTSTRAP_CMD=(clusterawsadm bootstrap iam create-cloudformation-stack)

if [[ -n "$CONFIG_FILE" ]]; then
    BOOTSTRAP_CMD+=(--config "$CONFIG_FILE")
fi

if [[ "$ENABLE_EKS" == "true" ]]; then
    # EKS requires additional IAM permissions
    BOOTSTRAP_CMD+=(--bootstrap-config-file /dev/stdin)
    EKS_CONFIG=$(cat <<'EOF'
apiVersion: bootstrap.aws.infrastructure.cluster.x-k8s.io/v1beta1
kind: AWSIAMConfiguration
spec:
  eks:
    enable: true
    iamRoleCreation: true
    managedMachinePool:
      disable: false
    fargate:
      disable: false
EOF
)
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] echo '$EKS_CONFIG' | ${BOOTSTRAP_CMD[*]}"
    else
        echo ">> ${BOOTSTRAP_CMD[*]} (with EKS config)"
        echo "$EKS_CONFIG" | "${BOOTSTRAP_CMD[@]}"
    fi
else
    run "${BOOTSTRAP_CMD[@]}"
fi

#
# 2. Encode credentials
#
echo ""
echo "=== Encoding Credentials ==="

if [[ "$DRY_RUN" == "true" ]]; then
    echo "[DRY-RUN] clusterawsadm bootstrap credentials encode-as-profile"
    AWS_B64ENCODED_CREDENTIALS="<base64-encoded-credentials>"
else
    AWS_B64ENCODED_CREDENTIALS=$(clusterawsadm bootstrap credentials encode-as-profile)
fi

#
# 3. Print summary
#
echo ""
echo "=========================================="
echo "CAPA AWS Setup Complete"
echo "=========================================="
echo ""
echo "The following IAM resources were created via CloudFormation:"
echo "- IAM Roles: control-plane.cluster-api-provider-aws.sigs.k8s.io"
echo "             nodes.cluster-api-provider-aws.sigs.k8s.io"
echo "             controllers.cluster-api-provider-aws.sigs.k8s.io"
echo "- Instance Profiles for EC2 nodes"
echo "- IAM Policies with required CAPA permissions"
if [[ "$ENABLE_EKS" == "true" ]]; then
    echo "- EKS-specific IAM roles and policies"
fi
echo ""
echo "To initialize CAPA in your cluster, run:"
echo ""
echo "export AWS_B64ENCODED_CREDENTIALS='${AWS_B64ENCODED_CREDENTIALS}'"
echo "# CAPI providers are installed by the Lattice operator"
echo ""
echo "Or with Lattice, create a secret for the operator:"
echo ""
echo "kubectl create secret generic aws-credentials \\"
echo "  --namespace lattice-system \\"
echo "  --from-literal=credentials=\"\${AWS_B64ENCODED_CREDENTIALS}\""
echo ""
echo "Then create a LatticeCluster:"
echo ""
cat <<EOF
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: my-cluster
spec:
  provider:
    type: aws
    kubernetes:
      version: "1.32.0"
    config:
      aws:
        region: ${REGION}
        sshKeyName: <your-ssh-key>
        controlPlane:
          instanceType: m5.xlarge
        workers:
          instanceType: m5.large
  nodes:
    controlPlane: 3
    workers: 3
EOF
echo ""
