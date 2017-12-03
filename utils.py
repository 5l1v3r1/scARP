# -*- coding: utf-8 -*-
import os, netifaces, errno, datetime
from collections import OrderedDict
from scapy.all import srp, Ether, ARP

MAC_DATA_FILE = "mac_data.txt"


def get_mac_list(ip, interface, timeout=5, interval=0.3):
    available_mac_addresses = {}
    print(ip)
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=str(ip)), timeout=timeout, iface=interface,
                     inter=interval)
    for snd, rcv in ans:
        available_mac_addresses[rcv.sprintf(r"%Ether.src%")] = rcv.sprintf(r"%ARP.psrc%")
    return available_mac_addresses


def get_interfaces():
    availables = OrderedDict()
    interfaces = os.listdir('/sys/class/net/')
    for interface in interfaces:
        try:
            ip = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
        except KeyError:
            continue
        if ip and interface != 'lo':
            availables[interface] = ip
    return availables


def generic_request(message=""):
    while True:
        answer = input(message + " (y/n):").lower()
        if answer == "y":
            return True
        elif answer == "n":
            return False
        else:
            print('Invalid input. Enter y or n.')


def ip_replace_request(mac_addr):
    return generic_request("\nIP address of the " + str(mac_addr) + " has changed. Change the registry file as well?")


def addMac(mac):
    return generic_request("\nThe MAC address %s is new. Do you want to append it in the registry file?" % mac)


def oldIP(mac):
    return generic_request("\nIP address of the %s is old. Do you want to delete it from the registry file?" % mac)


def check(onlineMacs, auto_accept=False):
    try:
        try:
            f = open(MAC_DATA_FILE, 'r+')
        except (OSError, IOError) as e:
            if getattr(e, 'errno', 0) == errno.ENOENT:
                f = open(MAC_DATA_FILE, 'w+')
        txtList = f.readlines()
        macs = list(onlineMacs.keys())
        f.close()
        os.remove(MAC_DATA_FILE)
        newTxtList = []
        addMacsCompare = []
        iMAC = ""
        for i in txtList:
            for j in macs:
                iMAC = i.split("|")[0]
                iIP = i.split("|")[1].split("\n")[0]
                if iMAC == j and iIP == onlineMacs[j]:
                    newTxtList.append(i)
                    addMacsCompare.append(j)
                    break
                elif iMAC == j and iIP != onlineMacs[j]:
                    if auto_accept:
                        decision = True
                    else:
                        decision = ip_replace_request(j)
                    if (decision):
                        newTxtList.append("%s|%s|%s\n" % (
                        iMAC, onlineMacs[j], datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")))
                        addMacsCompare.append(iMAC)
                    else:
                        newTxtList.append(i)
                        addMacsCompare.append(iMAC)
                    break
                elif iMAC != j and iIP == onlineMacs[j]:
                    if auto_accept:
                        decision = True
                    else:
                        decision = oldIP(iMAC)
                    if (decision):
                        break
                    else:
                        newTxtList.append(i)
                        addMacsCompare.append(iMAC)
                        break
            else:
                newTxtList.append(i)
                addMacsCompare.append(iMAC)

        for i in macs:
            if i not in addMacsCompare:
                if auto_accept:
                    decision = True
                else:
                    decision = addMac(i)
                if (decision):
                    newTxtList.append("%s|%s|%s\n" % (i, onlineMacs[i], str(datetime.datetime.now())))


    except Exception as error:
        f = open(MAC_DATA_FILE, "w")
        f.writelines(txtList)
        f.close()
        print('Caught this error: ' + repr(error))
    else:
        f = open(MAC_DATA_FILE, "w+")
        f.writelines(newTxtList)
        f.close()
        change_ownership(sort=True)
        print("▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄")
        print("█       MAC       █      IP       █         LOG DATE         █")
        print("▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀")
        for item in parse_mac_data():
            print("█" + item[0].ljust(17) + "█" + item[1].ljust(15) + "█" + item[2].ljust(26) + "█")
        if parse_mac_data():
            print("▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀")


def change_ownership(sort=False):
    userhome = os.path.expanduser('~')
    username = os.path.split(userhome)[-1]
    if sort:
        os.popen('sort -t "|" -k 3r,3 ' + MAC_DATA_FILE + ' > log.txt')
        os.popen('mv log.txt ' + MAC_DATA_FILE)
    os.popen(('chown {0} ' + MAC_DATA_FILE).format(username))
    os.popen(('chgrp {0} ' + MAC_DATA_FILE).format(username))


def ip_mask_prompt(args):
    while True:
        try:
            mask = int(args.mask)
        except ValueError:
            args.mask = input('Please enter a valid mask value(1-32): ')
        else:
            if mask >= 33 or mask <= 0:
                args.mask = input('Please enter a valid mask value(1-32): ')
            else:
                return


def parse_mac_data():
    mac_data_list = []
    try:
        file_handle = open(MAC_DATA_FILE, "r")
    except FileNotFoundError:
        print(MAC_DATA_FILE + " is not present right now")
        return []
    for line in file_handle.read().splitlines():
        mac_data_list.append(line.split("|"))
    return mac_data_list
