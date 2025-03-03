# AntiScanNmap
the script is anti scan nmap he detecting a scan and blocking attack (scan) is available in windows and linux but not in Macos
##IN-PYTHON##
If no attack is detected then try to run it in admin or replace on line 143 sniff(prn=detect_nmap_scan, store=0) by sniff(prn=detect_nmap_scan, store=0, iface="Ethernet", promisc=True)
