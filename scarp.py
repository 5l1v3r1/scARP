# -*- coding: utf-8 -*-
import utils, argparse


def scarp():
    desc = """
                        _____  _____
                  /\   |  __ \|  __ \\
      ___  ___   /  \  | |__) | |__) |
     / __|/ __| / /\ \ |  _  /|  ___/
     \__ \ (__ / ____ \| | \ \| |
     |___/\___/_/    \_\_|  \_\_|

    Scans the given interface for the mac addresses it possesses"""
    ex = 'Example of Usage:' \
         + '\n\tsudo python3 scarp.py -i enp8s0 -m 16' \
         + '\n\tsudo python3 scarp.py -m 20 -a'
    parser = argparse.ArgumentParser(description=desc, epilog=ex, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--interface', '-i', default='', help='Name of the interface you want to scan, optional',
                        required=False)
    parser.add_argument('--mask', '-m', default='24', help='IP mask value(1-32, default:24), optional', required=False)
    parser.add_argument('--auto-accept', '-a', default=False, action='store_true',
                        help='Add found MAC addresses to the list automatically, optional', required=False)
    args = parser.parse_args()
    interfaces = utils.get_interfaces()
    utils.ip_mask_prompt(args)
    print("Available interfaces:")
    for i in range(len(interfaces)):
        print("---" + list(interfaces.keys())[i] + ": " + list(interfaces.values())[i])
    while (args.interface not in interfaces):
        args.interface = input("Please enter a valid interface name: ")
    onlineMacs = utils.get_mac_list(interfaces[args.interface] + '/' + args.mask, args.interface)
    utils.check(onlineMacs, args.auto_accept)


if __name__ == '__main__':
    scarp()
