Hi this project is 75% finished but i figured i would release it before i ship off


what it does
------------
-sniff http traffic for credit card info 
	-plan was to use the scapy_ssl module to sniff it
	-other plan was to generate a pcap file to sniff manually


Problems
--------
-for whatever reason mmyy CVV do not get detected im not sure why
	-made a test script and my regexs were fine so maybe scapy problem?


Main reason for releasing this is a basic template
--------------------------------------------------
if you manage to work on it and make it better than what i have feel free to DM me on insta would love to learn how you went about it and mistakes i made 
	-insta: KarmaSploit

requirements
-------------
Linux only!
Python 3
colorama
scapy(2.4.3)
re (regular expressions)
pyfiglet

instructions
--------------
run python3 creditcardsniffer.py
choose your interface
if you dont have gnome terminal you can either just '#' out the link code or update it to xterm 
