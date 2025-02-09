import subprocess
import re
import platform
import ipaddress

def get_network(cidr_ip):
    return str(ipaddress.ip_network(cidr_ip, strict=False))

def get_mac_address(system, interface):
    if system == "Linux":
        result = subprocess.run(['ip', 'link', 'show', interface], stdout=subprocess.PIPE)
        output = result.stdout.decode()
        mac_match = re.search(r'link/ether (\S+)', output)
        if mac_match:
            return mac_match.group(1)
        else:
            return None

    elif system == "Darwin":
        result = subprocess.run(['ifconfig', interface], stdout=subprocess.PIPE)
        output = result.stdout.decode()
        mac_match = re.search(r'ether (\S+)', output)
        if mac_match:
            return mac_match.group(1)
        else:
            return None
    else:
        print(f"Unsupported system: {system}")
        return None

def get_active_interface_and_gateway(system):
    if system == "Linux":
        result = subprocess.run(['ip', 'route'], stdout=subprocess.PIPE)
        output = result.stdout.decode()
        match = re.search(r'default via (\S+) dev (\S+)', output)
        if match:
            return match.group(2), match.group(1)
        else:
            return None
    elif system == "Darwin":
        result = subprocess.run(['netstat', '-rn'], stdout=subprocess.PIPE)
        output = result.stdout.decode()
        match = re.search(r'default\s+(\S+)\s+(\S+)\s+(\S+)', output)
        if match:
            return match.group(3), match.group(1)
        else:
            return None
    else:
        print(f"Unsupported system: {system}")
        return None

def get_ip_with_cidr(interface, system):
    if system == "Linux":
        result = subprocess.run(['ip', 'addr', 'show', interface], stdout=subprocess.PIPE)
        output = result.stdout.decode()
        ip_match = re.search(r'inet (\S+) ', output)
        if ip_match:
            ip_with_netmask = ip_match.group(1)
            return ip_with_netmask
        else:
            return None
    elif system == "Darwin":
        result = subprocess.run(['ifconfig', interface], stdout=subprocess.PIPE)
        output = result.stdout.decode()
        ip_match = re.search(r'inet (\S+)\s+netmask (\S+)', output)
        if ip_match:
            ip = ip_match.group(1)
            netmask = ip_match.group(2)
            cidr = sum([bin(int(x, 16)).count('1') for x in netmask.split(':')])
            return f"{ip}/{cidr}"
        else:
            return None
    else:
        print(f"Unsupported system: {system}")
        return None

def get_network_values():
    try:
        system = platform.system()
        interface, gateway = get_active_interface_and_gateway(system)
        if interface and gateway:
            mac = get_mac_address(system, interface)
            if not mac:
                print("Unable to get MAC.")
                return None
            ip_with_cidr = get_ip_with_cidr(interface, system)
            if ip_with_cidr:
                network = get_network(ip_with_cidr)
                ip = ip_with_cidr.split('/')[0]
                return {
                    "system": system,
                    "interface": interface,
                    "ip": ip,
                    "mac": mac,
                    "gateway": gateway,
                    "network": network
                }
            else:
                print("Unable to get IP and subnet information.")
                return None
        else:
            print("No active interface or gateway found.")
            return None
    except:
        return None

def main():
    net = get_network_values()
    if net:
        print(f"System: {net['system']}")
        print(f"Interface: {net['interface']}")
        print(f"IP: {net['ip']}")
        print(f"MAC: {net['mac']}")
        print(f"Network: {net['network']}")
        print(f"Gateway: {net['gateway']}")
    else:
        print('Failed to get net info')

if __name__ == "__main__":
    main()
