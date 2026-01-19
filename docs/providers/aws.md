# AWS Provider (CAPA)

Lattice uses [Cluster API Provider AWS (CAPA)](https://github.com/kubernetes-sigs/cluster-api-provider-aws) for provisioning Kubernetes clusters on AWS.

## Prerequisites

### 1. AWS Credentials

Export your AWS credentials:

```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_REGION="us-west-2"  # or your preferred region

# Optional: for temporary credentials
export AWS_SESSION_TOKEN="your-session-token"
```

### 2. IAM Instance Profiles

CAPA requires IAM instance profiles for EC2 instances. Use `clusterawsadm` to create them:

```bash
# Download clusterawsadm
curl -L https://github.com/kubernetes-sigs/cluster-api-provider-aws/releases/download/v2.10.0/clusterawsadm-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m) -o clusterawsadm
chmod +x clusterawsadm

# Bootstrap IAM resources (creates CloudFormation stack)
./clusterawsadm bootstrap iam create-cloudformation-stack
```

This creates the default IAM instance profiles:
- `control-plane.cluster-api-provider-aws.sigs.k8s.io`
- `nodes.cluster-api-provider-aws.sigs.k8s.io`

### 3. SSH Key Pair

Create an EC2 key pair for node access:

```bash
aws ec2 create-key-pair \
  --key-name lattice-key \
  --query 'KeyMaterial' \
  --output text > lattice-key.pem

chmod 400 lattice-key.pem
```

### 4. Credentials Secret

After the management cluster is running, create the CAPA credentials secret:

```bash
kubectl create secret generic capa-manager-bootstrap-credentials \
  -n capa-system \
  --from-literal=AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  --from-literal=AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
  --from-literal=AWS_REGION="$AWS_REGION"
```

## Cluster Configuration

Example `LatticeCluster` for AWS:

```yaml
apiVersion: lattice.dev/v1alpha1
kind: LatticeCluster
metadata:
  name: my-cluster
spec:
  provider:
    kubernetes:
      version: "1.32.0"
      bootstrap: kubeadm  # or rke2
    config:
      aws:
        region: "us-west-2"
        cpInstanceType: "m5.xlarge"
        workerInstanceType: "m5.large"
        sshKeyName: "lattice-key"

        # Optional: custom IAM profiles
        # cpIamInstanceProfile: "my-cp-profile"
        # workerIamInstanceProfile: "my-worker-profile"

        # Optional: use existing VPC
        # vpcId: "vpc-12345"
        # cpSubnetIds:
        #   - "subnet-aaa"
        #   - "subnet-bbb"
        # workerSubnetIds:
        #   - "subnet-ccc"

        # Optional: root volume config
        cpRootVolumeSizeGb: 100
        cpRootVolumeType: "gp3"
        workerRootVolumeSizeGb: 100
        workerRootVolumeType: "gp3"

        # Optional: custom AMI
        # amiId: "ami-12345"
  nodes:
    controlPlane: 3
    workers: 5
  endpoints:
    # host is auto-discovered from NLB
    grpcPort: 50051
    bootstrapPort: 8443
    service:
      type: LoadBalancer
```

## Network Architecture

- **API Server**: Exposed via Network Load Balancer (NLB)
- **VPC**: CAPA creates a new VPC by default, or use existing with `vpcId`
- **Subnets**: Public subnets for load balancers, private for nodes

## Cost Considerations

- NLB: ~$0.0225/hour + data processing
- EC2 instances: varies by type and region
- EBS volumes: ~$0.08/GB-month for gp3

## Troubleshooting

### IAM Permission Errors

Ensure your credentials have sufficient permissions. The `clusterawsadm` bootstrap creates the required IAM roles.

### Subnet Availability

When using existing VPC, ensure subnets span multiple availability zones for HA.

### Instance Capacity

Some instance types may have capacity constraints. Try a different AZ or instance type if you see `InsufficientInstanceCapacity` errors.
