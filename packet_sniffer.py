from scapy.all import sniff, IP, TCP, UDP
from PyQt5.QtCore import QThread, pyqtSignal
import logging

# Disable scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class PacketSniffer(QThread):
    packet_captured = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        try:
            # store=0 prevents RAM from filling up
            sniff(prn=self.process_packet, store=0, stop_filter=self.should_stop)
        except Exception as e:
            self.packet_captured.emit(f"Error starting sniffer: {e}")

    def should_stop(self, packet):
        return not self.running

    def process_packet(self, packet):
        if not self.running: return

        try:
            if IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
                
                # Basic Summary
                summary = f"📦 [{proto}] {src} -> {dst}"
                
                # Detect HTTP (Cleartext Traffic)
                if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                     summary += " [HTTP DETECTED]"
                
                self.packet_captured.emit(summary)
        except:
            pass

    def stop(self):
        self.running = False