# Network Anomaly Detector

A lightweight Network Anomaly Detection System built using Python, Scapy, SQLite, and Flask. The engine sniffs the network in real-time for any suspicious traffic at Layer 2 and Layer 7, logs security events to a local database, and alerts administrators through a web UI and push notifications via Discord webhooks. The goal was to try out something that can help advance my understanding about packets and networking and execute a cybersecurity related project that uses these concepts. Detailed writeup on this project can be found at: https://vnykctf.blogspot.com/2026/09/network-anomaly-detector.html

## 📌 Features

* **Packet Engine:** Uses `Scapy` to perform real-time packet capturing.
* **Device Discovery:** Tracks local MAC addresses to establish a baseline and flags when new hardware joins the network.
* **DNS Exfiltration & Beaconing Detection:** Inspects DNS query length (`>45 chars`) to detect potential data exfiltration/tunneling and monitors queries targeting high-risk TLDs (`.xyz`, `.top`, `.tk`).
* **Real-Time Alerting:** Sends instant alert payloads to a mobile/desktop Discord Webhook.
* **Web Dashboard:** A dark-mode Flask web application built with Bootstrap to monitor security events in real-time.


## 🛠️ Tech Stack

* **Language:** Python 3
* **Packet Capture:** Scapy
* **Backend Framework:** Flask
* **Database:** SQLite3
* **Alerting:** Discord Webhooks (REST API)
* **Frontend:** HTML5, Bootstrap 5


## 📂 Repository Structure

```text
Project3_NIDS/
├── app.py                # Flask Web Dashboard UI
├── detector.py           # Core Scapy Sniffer & SQLite Detection Engine
├── requirements.txt      # Python dependencies
├── .gitignore            # Excludes local databases & virtual environments
└── templates/
    └── index.html        # Bootstrap UI template
```


## 🚀 Installation & Setup
1. Clone the Repository

```bash
git clone [https://github.com/Vin-Sud/nad.git](https://github.com/Vin-Sud/nad.git)
cd nad
```

2. Set Up Virtual Environment & Dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. Configure Discord Webhook (Optional)

Edit detector.py and assign your Webhook URL:

```Python
DISCORD_WEBHOOK_URL = "[https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE](https://discord.com/api/webhooks/YOUR_
```

## 🧪 Testing & Execution
1. Launch the Engine & Dashboard

In Terminal 1 (Sniffer):

```Bash
sudo ./venv/bin/python detector.py
```

In Terminal 2 (Flask UI):

```Bash
python app.py
```

Access the dashboard in your browser at http://127.0.0.1:5000.

2. Simulate Attack Signals
Run a suspicious DNS lookup to trigger alert rules:

```Bash
dig suspicious-malware-c2-beaconing-domain-test-exfiltration.xyz
```
