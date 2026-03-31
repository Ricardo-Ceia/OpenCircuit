import socket
import subprocess
import concurrent.futures

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

def ping_ip(ip:str)->bool:
    result = subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            capture_output=True,
            text=True)

    return result.returncode==0

def ping_sweep(ips:list[str])->list[str]:
    res = []
    for ip in ips:
        print(f"pinging... IP:{ip}")
        if ping_ip(ip) is True:
            res.append(ip)
    return res

def ping_sweep_parallel(ips: list[str],workers: int=32)->list[str]:
    res = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {executor.submit(ping_ip,ip): ip for ip in ips}

        for future in concurrent.futures.as_completed(future_to_ip):
            ip=future_to_ip[future]
            print(f"pinging... IP:{ip}")
            try:
                if future.result():
                    res.append(ip)
            except:
                pass
    return res

def main():
    ips_to_sweep = generate_ips("192.168.1.0/24")
    print(ping_sweep_parallel(ips_to_sweep))
main()
