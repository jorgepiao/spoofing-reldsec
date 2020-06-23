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
	pass


def scanner_red(range,gateway):
	pass


def restore_arp(destip,sourceip,hwsrc,hwdst):
	pass


def arp_spoofing(hwdst,pdst,psrc):
	pass



def main():
	pass




if __name__ == '__main__':
	main()









