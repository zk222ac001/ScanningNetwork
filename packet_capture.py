'''
sniff: to capture packets.
IP:    to filter packets that contain IP layer.
TCP:   to filter packets that use TCP protocol.
'''
from scapy.all import sniff, IP, TCP 
from collections import defaultdict
# threading: used to run the packet capture in a background thread.
import threading
#queue: used to store captured packets safely between threads.
import queue

# Defines a class PacketCapture to encapsulate all the logic for packet sniffing
class PacketCapture:
    # constructor : Initialization
    def __init__(self):
        # packet_queue: thread-safe queue to store packets.
        self.packet_queue = queue.Queue()
        # stop_capture: an event flag used to signal when to stop the capture.
        self.stop_capture = threading.Event()        
    # packet_callback function: Called each time a packet is sniffed.
    def packet_callback(self, packet):
        # Checks if the packet contains both IP and TCP layers.
        if IP in packet and TCP in packet:
            # adds the packet to the queue.
            self.packet_queue.put(packet)
    # Starts packet capture on the specified network interface (default is "eth0" — common for Ethernet).
    def start_capture(self, interface="eth0"):
        # Starts the capture_thread in a new background thread, so it doesn't block the main program.
        def capture_thread():
            # iface: the network interface to sniff from.            
            sniff(iface=interface,
                  # prn=self.packet_callback: calls your callback function for each packet.
                  prn=self.packet_callback,
                  # store=0: do not store packets in memory (for performance).           
                  store=0,
                  # stop_filter: stops sniffing when self.stop_capture is set.
                  stop_filter=lambda _: self.stop_capture.is_set())
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        # set(): signals the thread to stop.
        self.stop_capture.set()
        # join(): waits for the capture thread to finish before continuing.
        self.capture_thread.join()
# Defines a new class called TrafficAnalyzer to analyze traffic flow and extract statistics.        
class TrafficAnalyzer:
    def __init__(self):
        # self.connections will store a list of connections for each IP/port tuple.
        self.connections = defaultdict(list)
        # Using defaultdict(list) ensures that if a key is missing, it starts as an empty list.
        # self.flow_stats holds statistics for each network flow.
        # A flow is defined by a tuple of source IP, destination IP, source port, and destination port.
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,  # packet_count: how many packets are in the flow.
            'byte_count': 0,    # byte_count: total size of packets.
            'start_time': None, # start_time: time of the first packet in the flow.
            'last_time': None   # last_time: time of the most recent packet.
        })
    # A method to analyze a single captured packet.
    def analyze_packet(self, packet):
        # Checks if the packet contains both IP and TCP layers.
        # Filters out irrelevant packets (e.g., ARP, ICMP).
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            # Extracts the source and destination IP addresses and TCP port numbers from the packet.
            flow_key = (ip_src, ip_dst, port_src, port_dst)
            # reates a unique identifier (flow_key) for the TCP flow.
            # Update flow statistics
            stats = self.flow_stats[flow_key]
            # retrieves (or initializes) the statistics dictionary for this flow.
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time
     
            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        return {
            'packet_size': len(packet),
            'flow_duration': stats['last_time'] - stats['start_time'],
            'packet_rate': stats['packet_count'] / (stats['last_time'] - stats['start_time']),
            'byte_rate': stats['byte_count'] / (stats['last_time'] - stats['start_time']),
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }