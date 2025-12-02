import traceback
import pcapy
import sys
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

def process_packet(header, data, decoder):
    """Process a single packet from a PCAP file."""
    # Decode the packet
    packet = decoder.decode(data)
    
    # Get the IP layer if it exists
    ip = packet.child()
    if not ip:
        return
    
    if ip.__class__.__name__ in ["ARP","Data","LLC"]:
        return
    
    # Extract basic information
    src_ip = ip.get_ip_src()
    dst_ip = ip.get_ip_dst()
    protocol = None
    # Count by protocol
    if ip.__class__.__name__ == 'IP':
        # Handle IPv4
        protocol = ip.get_ip_p()
    elif ip.__class__.__name__ == 'IP6':
        # Handle IPv6
        protocol = ip.get_next_header()
    
    # Get the transport layer
    transport = ip.child()
    if not transport:
        return
    
    # Process based on protocol
    if protocol == 6: #TCP
        src_port = transport.get_th_sport()
        dst_port = transport.get_th_dport()
        flags = transport.get_th_flags()
        flag_str = get_tcp_flags(flags)
        
        #print(f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} [Flags: {flag_str}]")
        
        # Check for payload data
        #payload = transport.get_data_as_string()
        #if payload:
        #    print(f"  Payload: {payload[:50]}...")
            
    elif protocol == 17: #UDP
        src_port = transport.get_uh_sport()
        dst_port = transport.get_uh_dport()
        
        #print(f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        # Check for payload data
        #payload = transport.get_data_as_string()
        #if payload:
        #    print(f"  Payload: {payload[:50]}...")
            
    elif protocol == 58: #ICMPv6
        icmp_type = transport.get_type()
        icmp_code = transport.get_code()
        
        #print(f"ICMP {src_ip} -> {dst_ip} [Type: {icmp_type}, Code: {icmp_code}]")

def get_tcp_flags(flags):
    """Convert TCP flags to a readable string."""
    flag_str = []
    if flags & 0x01: flag_str.append("FIN")
    if flags & 0x02: flag_str.append("SYN")
    if flags & 0x04: flag_str.append("RST")
    if flags & 0x08: flag_str.append("PSH")
    if flags & 0x10: flag_str.append("ACK")
    if flags & 0x20: flag_str.append("URG")
    return "|".join(flag_str) if flag_str else "None"

def read_pcap(pcap_file):
    """Read and process packets from a PCAP file."""
    try:
        # Open the PCAP file
        reader = pcapy.open_offline(pcap_file)
        
        # Determine the link type and select appropriate decoder
        link_type = reader.datalink()
        if link_type == pcapy.DLT_EN10MB:
            decoder = EthDecoder()
        elif link_type == pcapy.DLT_LINUX_SLL:
            decoder = LinuxSLLDecoder()
        else:
            print(f"Unsupported datalink type: {link_type}")
            return
        
        # Read and process packets
        print(f"Reading packets from {pcap_file}...")
        packet_count = 0
        
        # Loop through each packet in the PCAP file
        while True:
            try:
                (header, data) = reader.next()
                if not header:
                    break
                
                packet_count += 1
                if packet_count % 10000 == 0:
                    print(f"Processed {packet_count} packets...")
                
                process_packet(header, data, decoder)
                
            except pcapy.PcapError:
                # End of file
                break
            
        print(f"Finished processing {packet_count} packets")
        
    except Exception as e:
        print(f"Error processing PCAP file: {e}")
        traceback.print_exc()

def analyze_pcap(pcap_file):
    """Perform basic statistical analysis on a PCAP file."""
    try:
        # Open the PCAP file
        reader = pcapy.open_offline(pcap_file)

        # Create a PCAP writer to store packets
        writer = pcapy.open_dead(reader.datalink(), 65536)
        dumper = writer.dump_open("output.pcap")
        
        # Initialize counters
        packet_count = 0
        tcp_count = 0
        udp_count = 0
        icmp_count = 0
        other_count = 0
        
        # Determine the link type and select appropriate decoder
        link_type = reader.datalink()
        if link_type == pcapy.DLT_EN10MB:
            decoder = EthDecoder()
        elif link_type == pcapy.DLT_LINUX_SLL:
            decoder = LinuxSLLDecoder()
        else:
            print(f"Unsupported datalink type: {link_type}")
            return
        
        # Read and analyze packets
        while True:
            try:
                (header, data) = reader.next()
                if not header:
                    break
                
                packet_count += 1
                if packet_count % 100000 == 0:
                    print(f"Processed {packet_count} packets...")
                
                # Decode the packet
                packet = decoder.decode(data)
                
                # Get the IP layer if it exists
                ip = packet.child()
                if not ip:
                    other_count += 1
                    continue
                
                # Count by protocol
                if ip.__class__.__name__ == 'IP':
                    # Handle IPv4
                    protocol = ip.get_ip_p()
                    if protocol == 6: #TCP
                        tcp_count += 1
                        
                        # Remove TCP payload
                        transport = ip.child()
                        transport.contains(None)
                    elif protocol == 17: #UDP
                        udp_count += 1
                    elif protocol == 58: #ICMP
                        icmp_count += 1
                    else:
                        other_count += 1
                        
                elif ip.__class__.__name__ == 'IP6':
                    # Handle IPv6
                    protocol = ip.get_next_header()
                    if protocol == 6:  # TCP
                        tcp_count += 1
                    elif protocol == 17:  # UDP
                        udp_count += 1
                    elif protocol == 58:  # ICMPv6
                        icmp_count += 1
                    else:
                        other_count += 1
                else:
                    other_count += 1

                dumper.dump(header, data)
            except pcapy.PcapError:
                # End of file
                break
        
        # Print analysis results
        print(f"\nPCAP Analysis Summary for {pcap_file}:")
        print(f"Total Packets: {packet_count}")
        print(f"TCP Packets: {tcp_count} ({tcp_count/packet_count*100:.2f}%)")
        print(f"UDP Packets: {udp_count} ({udp_count/packet_count*100:.2f}%)")
        print(f"ICMP Packets: {icmp_count} ({icmp_count/packet_count*100:.2f}%)")
        print(f"Other Packets: {other_count} ({other_count/packet_count*100:.2f}%)")
        
    except Exception as e:
        print(f"Error analyzing PCAP file: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <pcap_file>")
        sys.exit(1)
        
    pcap_file = sys.argv[1]
    analyze_pcap(pcap_file)
