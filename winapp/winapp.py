from scapy.all import sniff
from scapy.all import IP, TCP
import requests
import time
import socket

FLASK_BACKEND_URL = "http://127.0.0.1:5000/api/log"

def log_activity(student_name, timestamp, url, message):
    data = {
        'studentName': student_name,
        'timestamp': timestamp,
        'url': url,
        'userMessages': [message]
    }
    try:
        response = requests.post(FLASK_BACKEND_URL, json=data)
        print(response)
        if response.status_code == 200:
            print(f"Logged successfully: {data}")
        else:
            print(f"Failed to log: {response.text}")
    except Exception as e:
        print(f"Error logging activity: {e}")

CHATGPT_IPS = {'104.18.37.228', '172.64.150.28', '172.64.155.209', '104.18.32.47'}


def packet_callback(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]


        # Check if the destination IP matches known ChatGPT IPs
        if ip_layer.dst in CHATGPT_IPS:
            print(f"Detected ChatGPT IP in packet: {packet.summary()}")

            # Log or handle the packet here
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
            student_name = socket.gethostname()
            url = 'https://chat.openai.com/'  # Example URL, adjust if needed
            message = "Detected ChatGPT request."

            log_activity(student_name, timestamp, url, message)


# Start sniffing (monitor only HTTPS traffic)
sniff(prn=packet_callback, filter="tcp port 443", store=0)
