#!/usr/bin/env python
#_*_ coding: utf8 _*_

from scapy.all import *
from colorama import Fore, init
import argparse
import sys

parse = argparse.ArgumentParser()
parse.add_argument("-r", "--range", help="Rango a escanear o spoofear")
parse.add_argument("-g", "--gateway", help="Gateway")
parse = parse.parse_args()


def get_mac(gateway):
	arp_layer = ARP(pdst=gateway)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	final_packet = broadcast / arp_layer

	mac = srp(final_packet, timeout=2, verbose=False)[0]
	mac = mac[0][1].hwsrc
	return mac


def scanner_red(rango,gateway):
	lista_hosts = dict()

	arp_layer = ARP(pdst=rango)
	broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
	final_packet = broadcast / arp_layer

	answers = srp(final_packet, timeout=2, verbose=False)[0]
	print('\n')

	for a in answers:
		print(a)


def restore_arp(destip,sourceip,hwsrc,hwdst):
	pass



def arp_spoofing(hwdst,pdst,psrc):
	pass



def main():
	if parse.range and parse.gateway:
		mac_gateway = get_mac(parse.gateway)
		print(mac_gateway)
		scanner_red(parse.range, parse.gateway)

	else:
		print("Necesito opciones")




if __name__ == '__main__':
	main()









