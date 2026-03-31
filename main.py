import socket

def generate_ips(subnet: str)->list[str]:
    base_ip,prefix = subnet.split('/')
    octets = base_ip.split('.')

    prefix_int = int(prefix)
    num_hosts = 2**(32-prefix_int)-2

    ips = []
    for i in range(1,num_hosts+1):
        ip = f"{octets[0]}.{octets[1]}.{octets[2]}.{i}"
        ips.append(ip)
    
    return ips

def main():
    print(generate_ips("192.168.1.0/24"))
main()
