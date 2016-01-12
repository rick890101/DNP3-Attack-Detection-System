__author__  = "David Olano"

''' IP operation functions '''

def calculate_ip_range(ip1,ip2):
    host_ip1 = int(remove_network_mask(ip1))
    host_ip2 = int(remove_network_mask(ip2))
    rangeIP = host_ip1 - host_ip2
    return abs(rangeIP)


def remove_network_mask(ip):
    ip_inversa = ip[len(ip):0:-1]
    host_ip = ip_inversa[0:ip_inversa.find('.')]
    host_ip = host_ip[::-1]
    return host_ip

    
