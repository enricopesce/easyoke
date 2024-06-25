# EeasyOKE project

## Automated Kubernetes Cluster Deployment on Oracle Cloud Infrastructure

This IaC code provides a simple way to deploy a OKE cluster on Oracle Cloud Infrastructure.

It is useful for starting without extensive expertise or as a foundation code ready to extend.

I used Pulumi as an IaC tool because, for various personal reasons, I prefer it over Terraform. However, don't worry; under the hood, Pulumi uses Terraform.

## Why EasyOKE?

The main requirements that motivated me to develop this code are as follows:

- **Simplicity**: I have customers who need to be up and running in minutes. We need a good blueprint to start without complexity and requiring a deep understanding.
- **Functionality**: Most online examples available are complex and non-functional. This code provides a working Kubernetes cluster.
- **Well-architected**: The template is designed to cover the best possible security practices, such as embracing all availability domains, restricted ACLs, native VCN networking etc.

## Why Pulumi?

I chose Pulumi because it is very easy to automate and develop logical implementatios. The main features are:

- Automatic creation of the VCN with subnetting calculation; you only need to define the supernet CIDR.
- Automatic discovery of all availability domains to best configure the OKE pools spread across all domains to obtain maximum availability.
- Kubernetes config file automagically generated, ready to use with `export KUBECONFIG=$PWD/kubeconfig`.

## Prerequisites

1. Install Pulumi CLI - https://www.pulumi.com/docs/get-started/install/
2. Install Python - https://www.python.org/downloads/
3. Install OCI CLI - https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliinstall.htm
4. Oracle credentilas for Pulumi - https://www.pulumi.com/registry/packages/oci/installation-configuration/

### Environment set-up

Clone this repository and downloads all Python requirements.

```
git clone https://github.com/enricopesce/easyoke.git
cd easyoke
pip install -r requirements.txt
```

## Configuring the stack

There are some configurations necessary to personalize the stack configuration.

Optional: Use local state file (if you don't save your data on pulumi cloud)

```
mkdir oci-stack-statefile
pulumi login file://oci-stack-statefile
```

Required config:

```
pulumi config set compartment_ocid "Your compartment ID"
```

Optional configs:

```
pulumi config set vcn_cidr_block "10.0.0.0/16"
pulumi config set node_shape "VM.Standard.E5.Flex"
pulumi config set kubernetes_version "v1.29.1"
pulumi config set oke_min_nodes "3"
pulumi config set node_image_id "ocid1.image.oc1.eu-frankfurt-1.aaaaaaaaxhd3lt7dttn22pwvhzyksgcm3mxbksnowz47b3oku5hbc6rlisvq"
pulumi config set oke_ocpus "2"
pulumi config set oke_memory_in_gbs "32"
```

I suggest to use all options to best fit you requirements.

## Deploy the stack

The deployment phase is very easy:

```
pulumi up
Please choose a stack, or create a new one: <create a new stack>
Please enter your desired stack name: oke 
Created stack 'oke'
```

The creation needs 10/15 minutes

## Configure kubectl

If the deployment is done, you can use directly the created kubeconfig file in the same path or copy where you prefer

```
chmod 600 kubeconfig
export KUBECONFIG=$PWD/kubeconfig
kubectl get pods -A

NAMESPACE     NAME                                   READY   STATUS    RESTARTS   AGE
kube-system   coredns-6d9c47d4f7-8pm78               1/1     Running   0          2m28s
kube-system   coredns-6d9c47d4f7-f85j5               1/1     Running   0          6m29s
kube-system   coredns-6d9c47d4f7-l8xwm               1/1     Running   0          2m28s
kube-system   csi-oci-node-fvmlj                     1/1     Running   0          4m21s
kube-system   csi-oci-node-gwsjb                     1/1     Running   0          4m42s
kube-system   csi-oci-node-lsztr                     1/1     Running   0          4m17s
kube-system   kube-dns-autoscaler-6c6897cd78-vpvqj   1/1     Running   0          6m28s
kube-system   kube-proxy-45bdm                       1/1     Running   0          4m17s
kube-system   kube-proxy-hkqnl                       1/1     Running   0          4m42s
kube-system   kube-proxy-zmcwn                       1/1     Running   0          4m21s
kube-system   proxymux-client-6z6hk                  1/1     Running   0          4m42s
kube-system   proxymux-client-c6lct                  1/1     Running   0          4m17s
kube-system   proxymux-client-sh2qd                  1/1     Running   0          4m21s
kube-system   vcn-native-ip-cni-bh8jn                1/1     Running   0          4m21s
kube-system   vcn-native-ip-cni-tlnfw                1/1     Running   0          4m42s
kube-system   vcn-native-ip-cni-xl74b                1/1     Running   0          4m17s
```

## Destroy the stack

The stack deletion is:

Delete the possible application load balancer (via OCI Console ) or clean the Kubernetes services (Using kubectl) before destroying the stack.

```
pulumi destroy
```
