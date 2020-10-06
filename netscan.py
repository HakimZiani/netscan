import argparse
import scapy.all as scapy

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",dest="target")
    return parser.parse_args()

def scan(ip):
    arp_packet = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    final_packet = broadcast/arp_packet
    answered = scapy.srp(final_packet , timeout=1,)[0]
    result=[]
    for answer in answered:
        result.append({"IP":answer[1].psrc,"MAC":answer[1].hwsrc})
    return result

def print_result(result):
    print("IP\t\t\tMac")
    print("--------------------------------------------")
    for res in result:
        print(res['IP']+"\t\t"+res["MAC"])
options = parse_arguments()
result = scan(options.target)
print_result(result)