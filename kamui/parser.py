import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    results = []

    for host in root.findall("host"):
        addr = host.find("address").get("addr")
        host_data = {"address": addr, "ports": []}
        
        for port in host.findall("ports/port"):
            p_id = port.get("portid")
            state = port.find("state").get("state")
            service = port.find("service").get("name") if port.find("service") is not None else "unknown"
            
            host_data["ports"].append({
                "port": p_id,
                "state": state,
                "service": service
            })
        results.append(host_data)
    return results