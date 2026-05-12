import nmap

def run_nmap_discovery(ip):
    nm = nmap.PortScanner()
    # NF 6.2: Ribojame pralaidumą (max-rate 100 paketas/sek)
    nm.scan(ip, arguments='-T3 --max-rate 100')
    return nm[ip]
