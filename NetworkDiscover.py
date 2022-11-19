import scapy.all as scapy
import argparse

def get_args():
    input = argparse.ArgumentParser()
    input.add_argument('-t', '--target', dest='target', help='Target IP Address/Adresses')
    choices = input.parse_args()

    if not choices.target:
        input.error("Mention something")
    return choices
  
def scan(ip):
    arp_rf = scapy.ARP(pdst = ip)

    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    
    final_f = broadcast_ether_frame / arp_rf

    final_list = scapy.srp(final_f, timeout = 1, verbose = False)[0]
    result = []
    for i in range(0,len(final_list)):
        client_dict = {"IP" : final_list[i][1].psrc, "MAC" : final_list[i][1].hwsrc}
        result.append(client_dict)

    return result
  
def display_result(result):
    
    for i in result:
        print("{}\t{}".format(i["IP"], i["MAC"]))
        
choices = get_args()
scanned_output = scan(choices.target)
display_result(scanned_output)
print(display_result)
