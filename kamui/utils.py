import ipaddress

def parse_targets(target_string):
    """
    Converts CIDR notations or single IPs into a list of individual IP strings.
    """
    try:
        # Handle CIDR (e.g., 10.0.0.0/24) or single IP
        network = ipaddress.ip_network(target_string, strict=False)
        return [str(ip) for ip in network.hosts()] if network.num_addresses > 1 else [str(network.network_address)]
    except ValueError:
        # Fallback for hostnames (e.g., scanme.nmap.org)
        return [target_string]