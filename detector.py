import sqlite3
import datetime
import requests
from scapy.all import sniff, IP, IPv6, Ether, DNS, DNSQR

# --- CONFIGURATION ---
DB_NAME = "alerts.db"
# Replace with your actual Discord Webhook URL (or leave blank to test locally)
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1547619515528122548/AYs183yU7EMtBKmLtm_WPk50mRMoHEspg4Q60Q881oWdMEP0m_nx1Py2d0KWHbd9RtMU" 

def send_discord_alert(message):
    """Sends a push notification to Discord if a webhook URL is configured."""
    if not DISCORD_WEBHOOK_URL:
        return
    payload = {"content": f"🚨 **NIDS ALERT:** {message}"}
    try:
        requests.post(DISCORD_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        print(f"[-] Failed to send Discord alert: {e}")

def init_db():
    """Initializes SQLite database tables for baseline devices and alerts."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Baseline table for known devices
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            first_seen TEXT,
            approved INTEGER DEFAULT 0
        )
    ''')
    
    # Table to store detection events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            src_mac TEXT,
            src_ip TEXT,
            details TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print("[+] Database initialized successfully.")

def log_alert(alert_type, src_mac, src_ip, details):
    """Logs an anomaly to the SQLite database and triggers a notification."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO alerts (timestamp, alert_type, src_mac, src_ip, details)
        VALUES (?, ?, ?, ?, ?)
    ''', (now, alert_type, src_mac, src_ip, details))
    conn.commit()
    conn.close()

    alert_msg = f"[{alert_type}] IP: `{src_ip}` | MAC: `{src_mac}` | Details: {details}"
    print(f"\n[🚨 ALERT] {alert_msg}")
    send_discord_alert(alert_msg)

def process_packet(packet):
    """Callback function executed on every captured network packet."""
    # Ensure packet has an Ethernet layer to extract source MAC
    if not packet.haslayer(Ether):
        return

    src_mac = packet[Ether].src
    src_ip = "N/A"
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src

    # --- ANOMALY 1: New/Unrecognized MAC Address ---
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE mac = ?", (src_mac,))
    device = cursor.fetchone()

    if not device:
        # First time seeing this device MAC
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO devices (mac, first_seen, approved) VALUES (?, ?, 0)", (src_mac, now))
        conn.commit()
        conn.close()
        log_alert("NEW_DEVICE_DETECTED", src_mac, src_ip, f"New device appeared on network.")
    else:
        conn.close()

    # --- ANOMALY 2: Suspicious DNS Query ---
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            query_name = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            
            # Rule A: Unusually long DNS domains (often DNS Tunneling or Exfiltration)
            if len(query_name) > 45:
                log_alert("SUSPICIOUS_DNS_LENGTH", src_mac, src_ip, f"Unusual domain length ({len(query_name)} chars): {query_name}")
            
            # Rule B: Flag suspicious TLDs often used by malware
            suspicious_tlds = ['.xyz', '.top', '.tk', '.biz', '.info']
            if any(query_name.endswith(tld) for tld in suspicious_tlds):
                log_alert("SUSPICIOUS_DNS_TLD", src_mac, src_ip, f"Query to risky TLD: {query_name}")

        except Exception:
            pass

if __name__ == "__main__":
    init_db()
    print("[*] Starting NIDS Traffic Sniffer... Press Ctrl+C to stop.")
    
    # Scapy sniffs packets continuously (store=0 saves RAM by not keeping packets in memory)
    try:
        sniff(prn=process_packet, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer.")
