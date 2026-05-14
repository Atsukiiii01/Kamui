import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError:
        raise ValueError("Failed to parse Nmap XML. The scan may have been interrupted.")

    results = []

    for host in root.findall("host"):
        # Prioritize IPv4, fallback to general address
        addr_element = host.find("address[@addrtype='ipv4']")
        if addr_element is None:
            addr_element = host.find("address")
            
        if addr_element is None:
            continue
            
        ip_addr = addr_element.get("addr")
        host_data = {"ip": ip_addr, "open_ports": []}
        
        for port in host.findall("ports/port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue  # Skip closed/filtered ports. We only want actionable vectors.
                
            p_id = port.get("portid")
            service_el = port.find("service")
            
            # Default empty values
            service_name = "unknown"
            product = ""
            version = ""
            extra = ""
            
            if service_el is not None:
                service_name = service_el.get("name", "unknown")
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                extra = service_el.get("extrainfo", "")
            
            # Clean up empty strings and build the port profile
            port_profile = {
                "port": p_id,
                "service": service_name,
            }
            if product: port_profile["product"] = product
            if version: port_profile["version"] = version
            if extra: port_profile["extra_info"] = extra
            
            host_data["open_ports"].append(port_profile)
        
        # Only add the host if it actually has open attack surfaces
        if host_data["open_ports"]:
            results.append(host_data)
            
    return {"targets": results, "total_hosts_with_open_ports": len(results)}
def parse_discovery_xml(xml_file):
    """Parses a ping sweep XML to extract only alive IP addresses."""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except ET.ParseError:
        raise ValueError("Failed to parse Discovery XML.")

    alive_ips = []
    for host in root.findall("host"):
        status = host.find("status")
        # Ensure the host is actually up
        if status is not None and status.get("state") == "up":
            addr_element = host.find("address[@addrtype='ipv4']")
            if addr_element is None:
                addr_element = host.find("address")
                
            if addr_element is not None:
                alive_ips.append(addr_element.get("addr"))
                
    return alive_ips