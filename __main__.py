import pulumi
import pulumi_oci as oci
import ipaddress
import re

###################################################################################################################################
# Utils
###################################################################################################################################


def get_oke_image(source, shape, oke_version):
    version = format_version(oke_version)
    if re.match("^VM\\.Standard\\.A\\d+\\.Flex", shape):
        pattern = f"(Oracle-Linux).*?(aarch64).*?({version})"
    elif re.match(".*GPU.*", shape):
        pattern = f"(Oracle-Linux).*?(GPU).*?({version})"
    else:
        pattern = f"(Oracle-Linux)-(?!.*?(?:GPU|aarch64)).*?({version})"
    return list(filter(lambda x: re.search(pattern, x["source_name"]), source))[0][
        "image_id"
    ]


def format_version(input_string):
    version_number = input_string.lstrip("v")
    formatted_version = re.sub(r"\.", r"\\.", version_number)
    return formatted_version


def get_ads(ads, net):
    z = []
    for ad in ads:
        z.append({"availability_domain": str(ad["name"]), "subnet_id": net})
    return z


def calculate_subnets(cidr, num_subnets):
    supernet = ipaddress.ip_network(cidr)
    new_prefix_length = supernet.prefixlen
    while (2 ** (new_prefix_length - supernet.prefixlen)) < num_subnets:
        new_prefix_length += 1
    subnets = list(supernet.subnets(new_prefix=new_prefix_length))
    subnet_strings = [str(subnet) for subnet in subnets[:num_subnets]]
    return subnet_strings


###################################################################################################################################
# Configuration variables
###################################################################################################################################

config = pulumi.Config()
compartment_id = config.require("compartment_ocid")
vcn_cidr_block = config.require("vcn_cidr_block")
node_shape = config.require("node_shape")
kubernetes_version = config.require("kubernetes_version")
oke_min_nodes = int(config.require("oke_min_nodes"))
node_image_id = config.require("node_image_id")
oke_ocpus = float(config.require("oke_ocpus"))
oke_memory_in_gbs = float(config.require("oke_memory_in_gbs"))
ssh_key = config.require("ssh_key")

(
    loadbalancers_subnet_address,
    public_subnet_address,
    pods_subnet_address,
    workers_subnet_address,
    oke_pods_cidr,
    oke_services_cidr,
) = calculate_subnets(vcn_cidr_block, 6)

###################################################################################################################################
# Infrastructure code
###################################################################################################################################

# Create a VCN
vcn = oci.core.Vcn(
    "vcn",
    compartment_id=compartment_id,
    cidr_block=vcn_cidr_block,
    display_name="vcn",
    dns_label="vcn",
)

# Create an Internet Gateway for the public subnet
internet_gateway = oci.core.InternetGateway(
    "InternetGateway",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    display_name="InternetGateway",
    enabled=True,
)

# Create a NAT Gateway for the private subnet
nat_gateway = oci.core.NatGateway(
    "NatGateway",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    display_name="NatGateway",
)

# Create a Service Gateway for access to OCI services
service_gateway = oci.core.ServiceGateway(
    "ServiceGateway",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    services=[
        oci.core.ServiceGatewayServiceArgs(
            service_id=oci.core.get_services().services[0].id
        )
    ],
    display_name="ServiceGateway",
)

###################################################################################################################################
# Network Security Groups (NSGs) - Oracle's recommended approach for IaC
# Reference: https://docs.oracle.com/en-us/iaas/Content/ContEng/Tasks/contengbestpractices_topic-Security-best-practices.htm
###################################################################################################################################

# Create NSG for API Endpoint (Public Subnet)
api_nsg = oci.core.NetworkSecurityGroup(
    "ApiEndpointNSG",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    display_name="ApiEndpointNSG",
)

# Create NSG for Worker Nodes
workers_nsg = oci.core.NetworkSecurityGroup(
    "WorkersNSG",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    display_name="WorkersNSG",
)

# Create NSG for Pods
pods_nsg = oci.core.NetworkSecurityGroup(
    "PodsNSG",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    display_name="PodsNSG",
)

# Create NSG for Load Balancers
loadbalancers_nsg = oci.core.NetworkSecurityGroup(
    "LoadBalancersNSG",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    display_name="LoadBalancersNSG",
)

###################################################################################################################################
# API Endpoint NSG Rules
###################################################################################################################################

# API Endpoint Ingress: Workers TCP/6443
api_ingress_workers_6443 = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiIngressWorkers6443",
    network_security_group_id=api_nsg.id,
    direction="INGRESS",
    protocol="6",
    source=workers_subnet_address,
    source_type="CIDR_BLOCK",
    description="Kubernetes worker to Kubernetes API endpoint communication.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=6443,
            max=6443,
        ),
    ),
)

# API Endpoint Ingress: Workers TCP/12250
api_ingress_workers_12250 = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiIngressWorkers12250",
    network_security_group_id=api_nsg.id,
    direction="INGRESS",
    protocol="6",
    source=workers_subnet_address,
    source_type="CIDR_BLOCK",
    description="Kubernetes worker to control plane communication.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=12250,
            max=12250,
        ),
    ),
)

# API Endpoint Ingress: Workers ICMP path discovery
api_ingress_workers_icmp = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiIngressWorkersIcmp",
    network_security_group_id=api_nsg.id,
    direction="INGRESS",
    protocol="1",
    source=workers_subnet_address,
    source_type="CIDR_BLOCK",
    description="Path discovery",
    icmp_options=oci.core.NetworkSecurityGroupSecurityRuleIcmpOptionsArgs(
        type=3,
        code=4,
    ),
)

# API Endpoint Ingress: Pods TCP/6443
api_ingress_pods_6443 = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiIngressPods6443",
    network_security_group_id=api_nsg.id,
    direction="INGRESS",
    protocol="6",
    source=pods_subnet_address,
    source_type="CIDR_BLOCK",
    description="Pod to Kubernetes API endpoint communication (VCN-native pod networking).",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=6443,
            max=6443,
        ),
    ),
)

# API Endpoint Ingress: Pods TCP/12250
api_ingress_pods_12250 = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiIngressPods12250",
    network_security_group_id=api_nsg.id,
    direction="INGRESS",
    protocol="6",
    source=pods_subnet_address,
    source_type="CIDR_BLOCK",
    description="Pod to Kubernetes API endpoint communication (VCN-native pod networking).",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=12250,
            max=12250,
        ),
    ),
)

# API Endpoint Ingress: External access TCP/6443
# Note: Consider restricting this to specific CIDR blocks for production
api_ingress_external_6443 = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiIngressExternal6443",
    network_security_group_id=api_nsg.id,
    direction="INGRESS",
    protocol="6",
    source="0.0.0.0/0",
    source_type="CIDR_BLOCK",
    description="External access to Kubernetes API endpoint.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=6443,
            max=6443,
        ),
    ),
)

# API Endpoint Egress: OCI Services
api_egress_oci_services = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiEgressOciServices",
    network_security_group_id=api_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination=oci.core.get_services().services[0].cidr_block,
    destination_type="SERVICE_CIDR_BLOCK",
    description="Allow Kubernetes API endpoint to communicate with OKE.",
)

# API Endpoint Egress: OCI Services ICMP
api_egress_oci_services_icmp = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiEgressOciServicesIcmp",
    network_security_group_id=api_nsg.id,
    direction="EGRESS",
    protocol="1",
    destination=oci.core.get_services().services[0].cidr_block,
    destination_type="SERVICE_CIDR_BLOCK",
    description="Path discovery",
    icmp_options=oci.core.NetworkSecurityGroupSecurityRuleIcmpOptionsArgs(
        type=3,
        code=4,
    ),
)

# API Endpoint Egress: Workers TCP/10250
api_egress_workers_10250 = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiEgressWorkers10250",
    network_security_group_id=api_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination=workers_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Allow Kubernetes API endpoint to communicate with worker nodes.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=10250,
            max=10250,
        ),
    ),
)

# API Endpoint Egress: Workers ICMP
api_egress_workers_icmp = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiEgressWorkersIcmp",
    network_security_group_id=api_nsg.id,
    direction="EGRESS",
    protocol="1",
    destination=workers_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Path discovery",
    icmp_options=oci.core.NetworkSecurityGroupSecurityRuleIcmpOptionsArgs(
        type=3,
        code=4,
    ),
)

# API Endpoint Egress: Pods ALL
api_egress_pods_all = oci.core.NetworkSecurityGroupSecurityRule(
    "ApiEgressPodsAll",
    network_security_group_id=api_nsg.id,
    direction="EGRESS",
    protocol="all",
    destination=pods_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Allow Kubernetes API endpoint to communicate with pods (VCN-native pod networking).",
)

###################################################################################################################################
# Workers NSG Rules
###################################################################################################################################

# Workers Ingress: API Endpoint TCP/10250
workers_ingress_api_10250 = oci.core.NetworkSecurityGroupSecurityRule(
    "WorkersIngressApi10250",
    network_security_group_id=workers_nsg.id,
    direction="INGRESS",
    protocol="6",
    source=public_subnet_address,
    source_type="CIDR_BLOCK",
    description="Allow Kubernetes API endpoint to communicate with worker nodes.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=10250,
            max=10250,
        ),
    ),
)

# Workers Ingress: ICMP path discovery from API endpoint
workers_ingress_api_icmp = oci.core.NetworkSecurityGroupSecurityRule(
    "WorkersIngressApiIcmp",
    network_security_group_id=workers_nsg.id,
    direction="INGRESS",
    protocol="1",
    source=public_subnet_address,
    source_type="CIDR_BLOCK",
    description="Path discovery",
    icmp_options=oci.core.NetworkSecurityGroupSecurityRuleIcmpOptionsArgs(
        type=3,
        code=4,
    ),
)

# Workers Ingress: Load Balancers NodePort range
workers_ingress_lb_nodeports = oci.core.NetworkSecurityGroupSecurityRule(
    "WorkersIngressLbNodePorts",
    network_security_group_id=workers_nsg.id,
    direction="INGRESS",
    protocol="6",
    source=loadbalancers_subnet_address,
    source_type="CIDR_BLOCK",
    description="Load balancer to worker nodes node ports.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=30000,
            max=32767,
        ),
    ),
)

# Workers Ingress: Load Balancers kube-proxy health check (fixed port range)
workers_ingress_lb_kubeproxy = oci.core.NetworkSecurityGroupSecurityRule(
    "WorkersIngressLbKubeProxy",
    network_security_group_id=workers_nsg.id,
    direction="INGRESS",
    protocol="6",
    source=loadbalancers_subnet_address,
    source_type="CIDR_BLOCK",
    description="Allow load balancer to communicate with kube-proxy on worker nodes.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=10256,
            max=10256,
        ),
    ),
)

# Workers Egress: Pods ALL (fixed to use 'all' protocol)
workers_egress_pods_all = oci.core.NetworkSecurityGroupSecurityRule(
    "WorkersEgressPodsAll",
    network_security_group_id=workers_nsg.id,
    direction="EGRESS",
    protocol="all",
    destination=pods_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Allow worker nodes to access pods.",
)

# Workers Egress: ICMP path discovery
workers_egress_icmp = oci.core.NetworkSecurityGroupSecurityRule(
    "WorkersEgressIcmp",
    network_security_group_id=workers_nsg.id,
    direction="EGRESS",
    protocol="1",
    destination="0.0.0.0/0",
    destination_type="CIDR_BLOCK",
    description="Path discovery",
    icmp_options=oci.core.NetworkSecurityGroupSecurityRuleIcmpOptionsArgs(
        type=3,
        code=4,
    ),
)

# Workers Egress: OCI Services
workers_egress_oci_services = oci.core.NetworkSecurityGroupSecurityRule(
    "WorkersEgressOciServices",
    network_security_group_id=workers_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination=oci.core.get_services().services[0].cidr_block,
    destination_type="SERVICE_CIDR_BLOCK",
    description="Allow worker nodes to communicate with OKE.",
)

# Workers Egress: API Endpoint TCP/6443
workers_egress_api_6443 = oci.core.NetworkSecurityGroupSecurityRule(
    "WorkersEgressApi6443",
    network_security_group_id=workers_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination=public_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Kubernetes worker to Kubernetes API endpoint communication.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=6443,
            max=6443,
        ),
    ),
)

# Workers Egress: API Endpoint TCP/12250
workers_egress_api_12250 = oci.core.NetworkSecurityGroupSecurityRule(
    "WorkersEgressApi12250",
    network_security_group_id=workers_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination=public_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Kubernetes worker to Kubernetes API endpoint communication.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=12250,
            max=12250,
        ),
    ),
)

# Workers Egress: Internet HTTPS for container registries
workers_egress_internet_https = oci.core.NetworkSecurityGroupSecurityRule(
    "WorkersEgressInternetHttps",
    network_security_group_id=workers_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination="0.0.0.0/0",
    destination_type="CIDR_BLOCK",
    description="Access to external (ex Docker) container registry",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=443,
            max=443,
        ),
    ),
)

###################################################################################################################################
# Pods NSG Rules
###################################################################################################################################

# Pods Ingress: Workers ALL
pods_ingress_workers_all = oci.core.NetworkSecurityGroupSecurityRule(
    "PodsIngressWorkersAll",
    network_security_group_id=pods_nsg.id,
    direction="INGRESS",
    protocol="all",
    source=workers_subnet_address,
    source_type="CIDR_BLOCK",
    description="Allow worker nodes to access pods.",
)

# Pods Ingress: API Endpoint ALL
pods_ingress_api_all = oci.core.NetworkSecurityGroupSecurityRule(
    "PodsIngressApiAll",
    network_security_group_id=pods_nsg.id,
    direction="INGRESS",
    protocol="all",
    source=public_subnet_address,
    source_type="CIDR_BLOCK",
    description="Allow Kubernetes API endpoint to communicate with pods.",
)

# Pods Ingress: Inter-pod ALL
pods_ingress_pods_all = oci.core.NetworkSecurityGroupSecurityRule(
    "PodsIngressPodsAll",
    network_security_group_id=pods_nsg.id,
    direction="INGRESS",
    protocol="all",
    source=pods_subnet_address,
    source_type="CIDR_BLOCK",
    description="Allow pods to communicate with other pods.",
)

# Pods Egress: Inter-pod ALL
pods_egress_pods_all = oci.core.NetworkSecurityGroupSecurityRule(
    "PodsEgressPodsAll",
    network_security_group_id=pods_nsg.id,
    direction="EGRESS",
    protocol="all",
    destination=pods_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Allow pods to communicate with other pods.",
)

# Pods Egress: OCI Services ICMP
pods_egress_oci_services_icmp = oci.core.NetworkSecurityGroupSecurityRule(
    "PodsEgressOciServicesIcmp",
    network_security_group_id=pods_nsg.id,
    direction="EGRESS",
    protocol="1",
    destination=oci.core.get_services().services[0].cidr_block,
    destination_type="SERVICE_CIDR_BLOCK",
    description="Path discovery",
    icmp_options=oci.core.NetworkSecurityGroupSecurityRuleIcmpOptionsArgs(
        type=3,
        code=4,
    ),
)

# Pods Egress: OCI Services TCP
pods_egress_oci_services = oci.core.NetworkSecurityGroupSecurityRule(
    "PodsEgressOciServices",
    network_security_group_id=pods_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination=oci.core.get_services().services[0].cidr_block,
    destination_type="SERVICE_CIDR_BLOCK",
    description="Allow pods to communicate with OCI services.",
)

# Pods Egress: Internet HTTPS (optional)
pods_egress_internet_https = oci.core.NetworkSecurityGroupSecurityRule(
    "PodsEgressInternetHttps",
    network_security_group_id=pods_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination="0.0.0.0/0",
    destination_type="CIDR_BLOCK",
    description="(optional) Allow pods to communicate with internet.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=443,
            max=443,
        ),
    ),
)

# Pods Egress: API Endpoint TCP/6443
pods_egress_api_6443 = oci.core.NetworkSecurityGroupSecurityRule(
    "PodsEgressApi6443",
    network_security_group_id=pods_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination=public_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Pod to Kubernetes API endpoint communication (VCN-native pod networking).",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=6443,
            max=6443,
        ),
    ),
)

# Pods Egress: API Endpoint TCP/12250
pods_egress_api_12250 = oci.core.NetworkSecurityGroupSecurityRule(
    "PodsEgressApi12250",
    network_security_group_id=pods_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination=public_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Pod to Kubernetes API endpoint communication (VCN-native pod networking).",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=12250,
            max=12250,
        ),
    ),
)

###################################################################################################################################
# Load Balancers NSG Rules
###################################################################################################################################

# Load Balancers Ingress: Internet HTTPS
lb_ingress_internet_https = oci.core.NetworkSecurityGroupSecurityRule(
    "LbIngressInternetHttps",
    network_security_group_id=loadbalancers_nsg.id,
    direction="INGRESS",
    protocol="6",
    source="0.0.0.0/0",
    source_type="CIDR_BLOCK",
    description="Load balancer listener protocol and port. Customize as required.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=443,
            max=443,
        ),
    ),
)

# Load Balancers Ingress: Internet HTTP
lb_ingress_internet_http = oci.core.NetworkSecurityGroupSecurityRule(
    "LbIngressInternetHttp",
    network_security_group_id=loadbalancers_nsg.id,
    direction="INGRESS",
    protocol="6",
    source="0.0.0.0/0",
    source_type="CIDR_BLOCK",
    description="Load balancer listener protocol and port. Customize as required.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=80,
            max=80,
        ),
    ),
)

# Load Balancers Egress: Workers NodePort range
lb_egress_workers_nodeports = oci.core.NetworkSecurityGroupSecurityRule(
    "LbEgressWorkersNodePorts",
    network_security_group_id=loadbalancers_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination=workers_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Load balancer to worker nodes node ports.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=30000,
            max=32767,
        ),
    ),
)

# Load Balancers Egress: Workers kube-proxy health check
lb_egress_workers_kubeproxy = oci.core.NetworkSecurityGroupSecurityRule(
    "LbEgressWorkersKubeProxy",
    network_security_group_id=loadbalancers_nsg.id,
    direction="EGRESS",
    protocol="6",
    destination=workers_subnet_address,
    destination_type="CIDR_BLOCK",
    description="Allow load balancer to communicate with kube-proxy on worker nodes.",
    tcp_options=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsArgs(
        destination_port_range=oci.core.NetworkSecurityGroupSecurityRuleTcpOptionsDestinationPortRangeArgs(
            min=10256,
            max=10256,
        ),
    ),
)

###################################################################################################################################
# Route Tables
###################################################################################################################################

# Create a Route Table for the private subnet with a route via the NAT Gateway
workers_route_table = oci.core.RouteTable(
    "WorkersRouteTable",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    display_name="WorkersRouteTable",
    route_rules=[
        oci.core.RouteTableRouteRuleArgs(
            destination="0.0.0.0/0",
            network_entity_id=nat_gateway.id,
        ),
        oci.core.RouteTableRouteRuleArgs(
            destination=oci.core.get_services().services[0].cidr_block,
            destination_type="SERVICE_CIDR_BLOCK",
            network_entity_id=service_gateway.id,
        ),
    ],
)

# Create a Route Table for the public subnet with a route via the Internet Gateway
public_route_table = oci.core.RouteTable(
    "PublicRouteTable",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    display_name="PublicRouteTable",
    route_rules=[
        oci.core.RouteTableRouteRuleArgs(
            destination="0.0.0.0/0",
            network_entity_id=internet_gateway.id,
        ),
    ],
)

# Create a Route Table for the loadbalancers subnet with a route via the Internet Gateway
loadbalancers_route_table = oci.core.RouteTable(
    "LoadBalancersRouteTable",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    display_name="LoadBalancersRouteTable",
    route_rules=[
        oci.core.RouteTableRouteRuleArgs(
            destination="0.0.0.0/0",
            network_entity_id=internet_gateway.id,
        ),
    ],
)

# Create a Public Subnet within the VCN
public_subnet = oci.core.Subnet(
    "PublicSubnet",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    cidr_block=public_subnet_address,
    display_name="PublicSubnet",
    dns_label="public",
    prohibit_public_ip_on_vnic=False,
    route_table_id=public_route_table.id,
)

# Create a Private Subnet within the VCN
workers_subnet = oci.core.Subnet(
    "WorkersSubnet",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    cidr_block=workers_subnet_address,
    display_name="WorkersSubnet",
    dns_label="workers",
    prohibit_public_ip_on_vnic=True,
    route_table_id=workers_route_table.id,
)

# Create a Pods Subnet within the VCN
pods_subnet = oci.core.Subnet(
    "PodsSubnet",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    cidr_block=pods_subnet_address,
    display_name="PodsSubnet",
    dns_label="pods",
    prohibit_public_ip_on_vnic=True,
    route_table_id=workers_route_table.id,
)

# Create a LoadBalancers Subnet within the VCN
loadbalancers_subnet = oci.core.Subnet(
    "LoadBalancersSubnet",
    compartment_id=compartment_id,
    vcn_id=vcn.id,
    cidr_block=loadbalancers_subnet_address,
    display_name="LoadBalancersSubnet",
    dns_label="loadbalancers",
    prohibit_public_ip_on_vnic=False,
    route_table_id=loadbalancers_route_table.id,
)

# Create the OKE cluster
oke_cluster = oci.containerengine.Cluster(
    "OkeCluster",
    compartment_id=compartment_id,
    name="OkeCluster",
    kubernetes_version=kubernetes_version,
    options=oci.containerengine.ClusterOptionsArgs(
        service_lb_subnet_ids=[loadbalancers_subnet.id],
        kubernetes_network_config=oci.containerengine.ClusterOptionsKubernetesNetworkConfigArgs(
            pods_cidr="10.2.0.0/16",
            services_cidr="10.3.0.0/16",
        ),
    ),
    cluster_pod_network_options=[
        oci.containerengine.ClusterClusterPodNetworkOptionArgs(
            cni_type="OCI_VCN_IP_NATIVE",
        )
    ],
    type="BASIC_CLUSTER",
    vcn_id=vcn.id,
    endpoint_config=oci.containerengine.ClusterEndpointConfigArgs(
        subnet_id=public_subnet.id, is_public_ip_enabled=True
    ),
)

if node_image_id == "":
    test_node_pool_option = oci.containerengine.get_node_pool_option_output(
        node_pool_option_id=oke_cluster.id, compartment_id=compartment_id
    )

    c = test_node_pool_option.sources
    node_image_id = c.apply(
        lambda images: get_oke_image(images, node_shape, kubernetes_version)
    )


get_ad_names = oci.identity.get_availability_domains_output(
    compartment_id=compartment_id
)
ads = get_ad_names.availability_domains

# Create a node pool
node_pool = oci.containerengine.NodePool(
    "NodePool",
    name="NodePool",
    cluster_id=oke_cluster.id,
    compartment_id=compartment_id,
    kubernetes_version=kubernetes_version,
    node_config_details=oci.containerengine.NodePoolNodeConfigDetailsArgs(
        placement_configs=ads.apply(lambda ads: get_ads(ads, workers_subnet.id)),
        size=oke_min_nodes,
        node_pool_pod_network_option_details=oci.containerengine.NodePoolNodeConfigDetailsNodePoolPodNetworkOptionDetailsArgs(
            cni_type="OCI_VCN_IP_NATIVE", pod_subnet_ids=[pods_subnet.id]
        ),
    ),
    node_shape=node_shape,
    node_shape_config=oci.containerengine.NodePoolNodeShapeConfigArgs(
        memory_in_gbs=oke_memory_in_gbs, ocpus=oke_ocpus
    ),
    node_source_details=oci.containerengine.NodePoolNodeSourceDetailsArgs(
        image_id=node_image_id,
        source_type="IMAGE",
    ),
    ssh_public_key=ssh_key if ssh_key else None,
)

# Retrieve the kubeconfig
cluster_kube_config = oke_cluster.id.apply(
    lambda cid: oci.containerengine.get_cluster_kube_config(cluster_id=cid)
)

cluster_kube_config.content.apply(lambda cc: open("kubeconfig", "w+").write(cc))

pulumi.export("vcn_id", vcn.id)
pulumi.export("internet_gateway_id", internet_gateway.id)
pulumi.export("nat_gateway_id", nat_gateway.id)
pulumi.export("service_gateway_id", service_gateway.id)
pulumi.export("public_subnet_id", public_subnet.id)
pulumi.export("pods_subnet_id", pods_subnet.id)
pulumi.export("public_security_list_id", public_security_list.id)
pulumi.export("workers_security_list_id", workers_security_list.id)
pulumi.export("pods_security_list_id", pods_security_list.id)
pulumi.export("cluster_id", oke_cluster.id)
pulumi.export("node_pool_id", node_pool.id)
