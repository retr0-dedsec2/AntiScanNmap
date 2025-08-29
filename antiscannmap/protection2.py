from scapy.all import *
import datetime
import threading
import time
import requests

# URL du webhook (exemple pour Discord)
WEBHOOK_URL = input("Enter Your Webhook-Url : ")

# Variables de détection des attaques
attack_active = False
attack_ongoing = False
last_attack_time = None
attack_timeout = 10
attacker_ip = None
victim_ip = None

# Liste des IPs à ignorer (elles ne déclenchent pas d'alerte mais sont toujours surveillées) PENSEZ A ENTREZ LE IP A BLOCK3 (your enter ip to block)
IGNORED_IPS = {""}

# Dictionnaire pour stocker les paquets suspects
suspicious_ips = {}
ALERT_THRESHOLD = 5  # Seuil avant déclenchement d'une alerte

# Fonction pour envoyer des alertes via webhook
def send_webhook_alert(message):
    try:
        data = {"content": message}
        response = requests.post(WEBHOOK_URL, json=data)

        if response.status_code in [200, 204]:
            print(f"[INFO] Webhook envoyé avec succès : {message}")
        else:
            print(f"[ERREUR] Échec de l'envoi du webhook : {response.status_code} {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"[ERREUR] Exception lors de l'envoi du webhook : {e}")

# Fonction pour enregistrer une alerte dans les logs et envoyer au webhook
def log_alert(message):
    print(message)
    with open("nmap_alerts.log", "a") as log_file:
        log_file.write(f"{datetime.datetime.now()}: {message}\n")
    send_webhook_alert(message)  # Envoi au webhook

# Fonction pour détecter la fin d'une attaque
def stop_attack():
    global attack_active, attack_ongoing
    if attack_active:
        log_alert(f"[INFO] Attaque stoppée : {attacker_ip} -> {victim_ip}")
        attack_active = False
        attack_ongoing = False

# Timer pour détecter la fin de l'attaque
def reset_attack_timer():
    global last_attack_time, attack_ongoing
    last_attack_time = datetime.datetime.now()

    def check_timeout():
        while attack_ongoing:
            if last_attack_time and (datetime.datetime.now() - last_attack_time).total_seconds() > attack_timeout:
                stop_attack()
                break
            time.sleep(1)

    threading.Thread(target=check_timeout, daemon=True).start()


from collections import defaultdict

# Table de suivi des connexions TCP (par IP + ports)
connections = defaultdict(dict)

def connection_exists(packet):
    key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
    return key in connections and connections[key] == "ESTABLISHED"

def detect_nmap_scan(packet):
    global attacker_ip, victim_ip

    if packet.haslayer(TCP) and packet.haslayer(IP):
        attacker_ip = packet[IP].src
        victim_ip = packet[IP].dst
        tcp_flags = packet[TCP].flags
        suspicious_packet = False

        # Mise à jour de l'état des connexions
        key = (attacker_ip, victim_ip, packet[TCP].sport, packet[TCP].dport)

        if tcp_flags == 0x02:  # SYN
            connections[key] = "SYN_SENT"

        elif tcp_flags == 0x12:  # SYN+ACK
            connections[key] = "SYN_ACK"

        elif tcp_flags == 0x10:  # ACK
            if key in connections and connections[key] == "SYN_ACK":
                connections[key] = "ESTABLISHED"
            elif not connection_exists(packet):
                suspicious_packet = True  # ACK scan

        # Détection des scans
        if tcp_flags == 0x02:  
            suspicious_packet = True  # SYN scan
        elif tcp_flags == 0x01:  
            suspicious_packet = True  # FIN scan
        elif tcp_flags == 0x00:  
            suspicious_packet = True  # NULL scan
        elif tcp_flags == 0x29:  
            suspicious_packet = True  # XMAS scan

        if suspicious_packet:
            suspicious_ips[attacker_ip] = suspicious_ips.get(attacker_ip, 0) + 1

            if not attack_active and suspicious_ips[attacker_ip] >= ALERT_THRESHOLD:
                attack_active = True
                attack_ongoing = True
                log_alert(f"[INFO] Attaque Nmap détectée : {attacker_ip} -> {victim_ip} et le flags tcp: flags=0x{tcp_flags:02x}" )
                reset_attack_timer()

# Capture des paquets réseau
try:
    print("[INFO] Surveillance en cours... (Ctrl+C pour arrêter)")
    sniff(prn=detect_nmap_scan, store=0)
except Exception as e:
    print(f"[ERREUR] Problème de capture des paquets : {e}")
