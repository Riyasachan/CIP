import scapy.all as scapy
from pycomm.ab_comm.slc import Driver as SlcDriver


# Define the IP address and port number of the honeypot:


HONEYPOT_IP = "0.0.0.0"
HONEYPOT_PORT = 44818


# Define the CIP packet structure:

cip_packet = scapy.Ether(dst="01:00:0c:cc:cc:cc") / \
             scapy.IP(dst=HONEYPOT_IP) / \
             scapy.UDP(sport=HONEYPOT_PORT, dport=HONEYPOT_PORT) / \
             scapy.Raw(load="test")




# Define the function that will handle incoming CIP requests and respond with a fake CIP response

def handle_cip_request(pkt):
    if pkt.haslayer(scapy.Raw):
        cip_request = pkt[scapy.Raw].load
        # Parse the CIP request
        slc_driver = SlcDriver()
        try:
            parsed_req = slc_driver.decode(cip_request)
            # Extract the requested service code and data
            service_code = parsed_req['command']
            data = parsed_req['data']
        except Exception as e:
            # Error handling
            print(f"Error parsing CIP request: {e}")
            return

        # Process the CIP request based on the service code
        if service_code == 0x4c:  # Read Tag Service
            # Extract the requested tag name from the data
            tag_name = data.decode().strip('\x00')
            # Generate a fake response containing the requested tag value
            fake_response = b"\x00\x4c\x00\x00\x00\x0e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

            scapy.send(fake_response, iface="eth0")
print("server started")
# Create a Scapy sniffing filter to capture incoming CIP traffic and call the handle_cip_request function:

cip_filter = "udp and dst port {}".format(HONEYPOT_PORT)
scapy.sniff(filter=cip_filter, prn=handle_cip_request)
