# TODO: Extract IP Addresses of source node, ultimate destination node, 
# and intermediate destination nodes.
# TODO: If multiple intermediate nodes exist, order them by hop count to source node in increasing order
# TODO: If multiple UDP msgs with same TTL hit different routers bc of load balancing,list all responding routers in exact order they appear in trace file
# TODO: FIlter protocols, Consider UDP, ICMP, ignore background packets involving TCP, DNS, STP
# TODO: Filter UDP Noise: Trace files may contain irrelevant UDP traffic like NBNS. Filter out by ensuring dest. ports all within trace route range
#       (dst_port >= 33434) && (dst_port <= 33529)
import io, os, struct, sys
import packet_struct

def parse_global_header(filename: str):
    try:
        # Open cap file
        f = open(filename, "rb")
    # End program if file does not exist
    except FileNotFoundError:
        print(f"File with name {filename} could not be found.")
        sys.exit(1)
    # Read global header
    global_header = f.read(24)
    # Header too small to be a global header, something is wrong, exit.
    if len(global_header) < 24:
        print("File too small to contain global header")
        sys.exit(1)

    # Grab magic number
    magic = struct.unpack("<I", global_header[:4])[0]
    if magic == 0xd4c3b2a1:
        #print("Swapped endian formatting")
        endian = ">"
    elif magic == 0xa1b2c3d4:
        #print("Native endian formatting")
        endian = "<"
    else:
        print(f"Unknown magic number {hex(magic)}")
        sys.exit(1)
    return endian, f

def parse_packets(endian: str, f: io.BufferedReader) -> list:
    packet_count = 0
    orig_time = None
    packets = []
    head_format = endian + "IIII"

    while(True):
        # Read packet header
        packet_header = f.read(16)
        packet_count += 1

        # Exit if data read is less than header size, i.e., end of file has been reached
        if len(packet_header) < 16:
            break

        # Extract header data
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(head_format, packet_header)
        time_absolute = ts_sec + (ts_usec * 0.000001)

        if orig_time == None:
            orig_time = time_absolute
        # Read packet data
        packet_data = f.read(incl_len)

        # Process packet data
        ip_packet = check_ip_and_process(
            packet_data,
            packet_count,
            time_absolute,
            orig_time
        )

        if ip_packet is not None:
            packets.append(ip_packet)
    f.close()
    return packets

def check_ip_and_process(data, count, time_absolute, orig_time):
    if len(data) < 34:
        return None
    
    protocol_val = struct.unpack('B', data[23:24])[0]

    # Filters out protocols that are not ICMP or UDP
    if protocol_val not in [1, 17]:
        return None
    
    # Create packet object
    packet = packet_struct.packet()
    packet.packet_No_set(count)
    packet.timestamp = round(time_absolute - orig_time, 6)

    ip = 14

    packet.IP_header.get_header_len(data[ip: ip + 1]) 
    packet.IP_header.get_total_len(data[ip + 2:ip + 4])

    # Extract IP addresses for destination and source
    packet.IP_header.get_IP(data[26:30], data[30:34])

    tcp = ip + packet.IP_header.ip_header_len
    if len(data) < tcp + 20:
        return None
    
    protocol = packet.IP_header.get_protocol(data[25:26])
    print(protocol)
    return packet

def group_into_connections(packet_list: list) -> dict:
    connection_dict = {}
    for packet in packet_list:
        if packet.IP_header.src_ip < packet.IP_header.dst_ip:
            key = (
                packet.IP_header.src_ip,
                packet.TCP_header.src_port,
                packet.IP_header.dst_ip,
                packet.TCP_header.dst_port
                )
        else:
            key = (
                packet.IP_header.dst_ip,
                packet.TCP_header.dst_port, 
                packet.IP_header.src_ip, 
                packet.TCP_header.src_port
                )

        if key not in connection_dict:
            connection_dict[key] = Connection(key)
        connection_dict[key].add_packet(packet)
    return connection_dict

def analyze_connections(connections: dict):

    complete_connections = []

    # Analyze state of every connection and create list of completed ones.
    for conn in connections.values():
        conn.analyze_state()

        if conn.is_complete:
            complete_connections.append(conn)

    return complete_connections

def print_report(connections: dict, complete_connections: list):
    print(f"A) Total number of connections: {len(connections)}")
    print()
    print("-" * 40)
    print()
    print("B) Connections' Details")
    print()
    reset_connections = 0
    before_capture = 0
    open_connections = 0
    count = 0
    for conn in connections.values():
        if count != 0:
            print("+" * 40)
        conn: Connection
        if conn.is_open():
            open_connections += 1
        if conn.rst_count >= 1:
            reset_connections += 1
        if conn.packets[0].TCP_header.flags.get("SYN") != 1:
            before_capture += 1
        count += 1
        
        print(f"Connection {count}:")
        print(f"Source Address: {conn.packets[0].IP_header.src_ip}")
        print(f"Destination Address: {conn.packets[0].IP_header.dst_ip}")
        print(f"Source Port: {conn.packets[0].TCP_header.src_port}")
        print(f"Destination Port: {conn.packets[0].TCP_header.dst_port}")
        print(f"Status: {conn.state}")
        if conn.is_complete:
            print(f"Start Time: {conn.start_time:.6f}s")
            print(f"End Time: {conn.end_time:.6f}s")
            print(f"Duration: {(conn.end_time - conn.start_time):.6f}s")
            print(f"Number of packets sent from Source to Destination: {conn.src_to_dst_packets}")
            print(f"Number of packets sent from Destination to Source: {conn.dst_to_src_packets}")
            print(f"Total Number of packets: {conn.src_to_dst_packets + conn.dst_to_src_packets}")
            print(f"Number of data bytes sent from Source to Destination: {conn.src_to_dst_bytes}B")
            print(f"Number of data bytes sent from Destination to Source: {conn.dst_to_src_bytes}B")
            print(f"Total Number of Data Bytes: {conn.dst_to_src_bytes + conn.src_to_dst_bytes}B")
        print("END")
    print()
    print("-" * 40)
    print()
    print("C) General")
    print()
    print(f"Total Number of Complete TCP Connections: {len(complete_connections)}")
    print(f"Total Number of Reset TCP Connections: {reset_connections}")
    print(f"Number of TCP Connections still open when the trace capture ended: {open_connections}")
    print(f"Number of TCP Connections established before the capture started: {before_capture}")
    print("-" * 40)
    complete_connection_statistics(complete_connections)

def complete_connection_statistics(complete_connections: list):
    durations = [c.end_time - c.start_time for c in complete_connections]
    rtts = [r for c in complete_connections for r in c.rtts]
    packets = [len(c.packets) for c in complete_connections]
    windows = [w for c in complete_connections for w in c.window_sizes]
    if not complete_connections:
        print("There were no complete TCP connections...")
        return
    print()
    print("D) Complete TCP Connections:")
    print()
    print(f"Minimum Time Duration: {min(durations):.6f}s")
    print(f"Mean Time Duration: {sum(durations) / len(durations):.6f}s")
    print(f"Maximum Time Duration: {max(durations):.6f}s")
    print()
    if rtts:
        print(f"Minimum RTT Value: {min(rtts):.6f}s")
        print(f"Mean RTT Value: {sum(rtts) / len(rtts):.6f}s")
        print(f"Maximum RTT Value: {max(rtts):.6f}s")
    else:
        print("Minimum RTT Value: N/A")
        print("Mean RTT Value: N/A")
        print("Maximum RTT Value: N/A")
    print()
    print(f"Minimum Number of Packets including both send/received: {min(packets)}")
    print(f"Mean Number of Packets including both send/received: {sum(packets) / len(packets):.6f}")
    print(f"Maximum Number of Packets including both send/received: {max(packets)}")
    print()
    print(f"Minimum Receive Window Size including both send/received: {min(windows)}B")
    print(f"Mean Receive Window Size including both send/received: {sum(windows) / len(windows):.6f}B")
    print(f"Maximum Receive Window Size including both send/received: {max(windows)}B")

if __name__ == "__main__":

    if len(sys.argv) == 2:
        filename = sys.argv[1] # If file provided in command line, use this one
    elif len(sys.argv) > 2: 
        print("Too many arguments:\nUsage: traceroute_analysis.py <path-to-capfile>")
        filename = None
    else:
        filename = None
    print(filename)
    endian, f = parse_global_header(filename)
    print(endian)
    packets = parse_packets(endian, f)
    check_ip_and_process(packets)

    


