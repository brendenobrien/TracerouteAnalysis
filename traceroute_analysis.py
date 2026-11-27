import math
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
    is_nano = False
    # Grab magic number
    magic = struct.unpack("<I", global_header[:4])[0]
    if magic == 0xd4c3b2a1:
        #print("Swapped endian formatting")
        endian = ">"
    elif magic == 0xa1b2c3d4:
        #print("Native endian formatting")
        endian = "<"
    elif magic == 0xa1b23c4d:
        endian = "<"
        is_nano = True
    elif magic == 0x4d3cb2a1:
        endian = ">"
        is_nano = True
    else:
        print(f"Unknown magic number {hex(magic)}")
        sys.exit(1)
    return endian, f, is_nano

def parse_packets(endian: str, f: io.BufferedReader, is_nano: bool) -> list:
    packet_count = 0
    orig_time = None
    packets = []
    head_format = endian + "IIII"
    ts_mult = 0.000000001 if is_nano else 0.000001

    while(True):
        # Read packet header
        packet_header = f.read(16)
        packet_count += 1

        # Exit if data read is less than header size, i.e., end of file has been reached
        if len(packet_header) < 16:
            break

        # Extract header data
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(head_format, packet_header)
        
        time_absolute = ts_sec + (ts_frac * ts_mult)

        if orig_time is None:
            orig_time = time_absolute
        # Read packet data
        packet_data = f.read(incl_len)

        # Process packet data
        ip_packet = check_ip_and_process(
            packet_data,
            packet_count,
            packet_header[0:4],
            packet_header[4:8],
            orig_time
        )

        if ip_packet is not None:
            ip_packet.timestamp = time_absolute
            packets.append(ip_packet)
    f.close()
    return packets

def check_ip_and_process(data, count, ts_sec_bytes, ts_usec_bytes, orig_time):
    if len(data) < 34:
        return None

    eth_type = struct.unpack('>H', data[12:14])[0]
    if eth_type != 0x0800:
        return None
    
    # Create packet object
    packet = packet_struct.packet()
    packet.packet_No_set(count)
    packet.timestamp_set(ts_sec_bytes, ts_usec_bytes, orig_time)

    ip = 14
    packet.IP_header.get_header_len(data[ip: ip + 1]) 
    ip_len = packet.IP_header.ip_header_len
    
    packet.IP_header.get_total_len(data[ip + 2:ip + 4])

    # Extract IP addresses for destination and source
    packet.IP_header.get_IP(data[26:30], data[30:34])

    packet.IP_header.get_protocol(data[23:24])
    packet.IP_header.get_fragmentation_info(data[18:20], data[20:22])

    protocol = packet.IP_header.protocol
    if protocol not in [1, 17]:
        return None

    payload_ind = ip + ip_len

    if protocol == 17 and len(data) >= payload_ind + 4:
        packet.UDP_header = packet_struct.UDP_Header()
        packet.UDP_header.get_ports(data[payload_ind:payload_ind+4])

        if 33434 <= packet.UDP_header.dst_port <= 33529:
            packet.is_probe = True


    elif protocol == 1 and len(data) >= payload_ind+8:
        packet.ICMP_header = packet_struct.ICMP_Header()
        packet.ICMP_header.get_type_and_code(data[payload_ind:payload_ind+2])

        icmp_type = packet.ICMP_header.type
        if icmp_type == 8:
            packet.ICMP_header.get_sequence_num(data[payload_ind+6:payload_ind+8])
            packet.is_probe = True
        elif icmp_type in [11, 0, 3]:
            packet.is_error = True
            orig_ip_start = payload_ind+8

            if len(data) >= orig_ip_start + 20:
                orig_ihl = (data[orig_ip_start] & 0x0F) * 4
                orig_protocol = data[orig_ip_start+9]
                orig_payload_ind = orig_ip_start + orig_ihl


                if orig_protocol == 17 and len(data) >= orig_payload_ind + 2:
                    packet.embedded_match_key = \
                    struct.unpack('>H', data[orig_payload_ind: orig_payload_ind+2])[0]
                elif orig_protocol == 1 and len(data) >= orig_payload_ind + 8:
                    packet.embedded_match_key = \
                    struct.unpack('>H', data[orig_payload_ind+6:orig_payload_ind+8])[0]

            if icmp_type == 0 and not packet.embedded_match_key:
                packet.embedded_match_key = \
                struct.unpack('>H', data[payload_ind + 6: payload_ind+8])[0]

    return packet

def analyze_traceroute(parsed_packets: list):
    source_node = None;
    ultimate_dest = None;   
    intermediates = []
    protocols = set()

    frag_count = 0
    last_frag_offset = 0

    probes_sent = {}
    rtt_measurements = {}
    ult_rtts = []

    for p in parsed_packets:
        protocols.add(p.IP_header.protocol)
        if source_node is None:
            source_node = p.IP_header.src_ip

        if p.is_probe and p.IP_header.src_ip == source_node:
            ultimate_dest = p.IP_header.dst_ip


            offset = p.IP_header.frag_offset
            if p.IP_header.flags == 1 or offset > 0:
                if offset > last_frag_offset: last_frag_offset = offset
                if offset == 0: frag_count = 0
                frag_count += 1
            elif frag_count == 0:
                frag_count = 1 
            match_key = p.UDP_header.src_port if p.IP_header.protocol == 17 else p.ICMP_header.seq_num
            if match_key not in probes_sent: probes_sent[match_key] = []
            probes_sent[match_key].append(p.timestamp)
        elif p.is_error and p.IP_header.dst_ip == source_node:
            router_ip = p.IP_header.src_ip
            if router_ip != ultimate_dest and router_ip not in intermediates:
                intermediates.append(router_ip)
                rtt_measurements[router_ip] = []

            if p.embedded_match_key and p.embedded_match_key in probes_sent:
                for sent_time in probes_sent[p.embedded_match_key]:
                    rtt = round((p.timestamp - sent_time) * 1000, 6)

                    if router_ip == ultimate_dest:
                        ult_rtts.append(rtt)
                    else:
                        rtt_measurements[router_ip].append(rtt)
                del probes_sent[p.embedded_match_key]
    if frag_count == 1 and last_frag_offset == 0:
        pass

    return source_node, ultimate_dest, intermediates, protocols, frag_count, last_frag_offset, rtt_measurements, ult_rtts


def calculate_stats(rtt_list):
    if not rtt_list: return 0.0, 0.0
    mean = sum(rtt_list) / len(rtt_list)
    variance = sum((x - mean) ** 2 for x in rtt_list) / (len(rtt_list) - 1) if len(rtt_list) > 1 else 0.0
    return round(mean, 2), round(math.sqrt(variance), 2)

def generate_results(src, dst, routers, protos, fc, f_off, rtts, ult_rtts):
    print(f"The IP address of the source node: {src}")
    print(f"The IP address of the destination node: {dst}")
    
    if len(routers) > 0:
        print("The IP addresses of the intermediate destination nodes:")
        i = 1

        for r in routers:
            print(f"\trouter {i}: {routers[i - 1]}")
            i += 1

    print("\n\nThe values in the protocol field of the IP headers:")
    for p in sorted(list(protos)):
        name = "ICMP" if p == 1 else "UDP"
        print(f"\t{p}: {name}")

    print(f"\nThe number of fragments created from the original datagram is: {fc}")
    print(f"The offset of the last fragment is: {f_off} bytes\n")

    for router in routers:
        mean_rrt, sd_rtt = calculate_stats(rtts[router])
        mean_str = f"{mean_rrt:g}"
        sd_str = f"{sd_rtt:g}"
        print(f"The avg RTT between {src} and {router} is: {mean_str} ms, the s.d. is: {sd_str} ms")

    if ult_rtts:
        mean_ult, sd_ult = calculate_stats(ult_rtts)
        mean_str = f"{mean_ult:g}"
        sd_str = f"{sd_ult:g}"
        print(f"The avg RTT between {src} and {dst} is: {mean_str} ms, the s.d. is: {sd_str} ms")

if __name__ == "__main__":

    if len(sys.argv) == 2:
        filename = sys.argv[1] # If file provided in command line, use this one
    elif len(sys.argv) > 2: 
        print("Too many arguments:\nUsage: traceroute_analysis.py <path-to-capfile>")
        filename = None
    else:
        filename = None
    endian, f, is_nano = parse_global_header(filename)
    if f is None:
        sys.exit(1)

    packets = parse_packets(endian, f, is_nano)
    src, dst, routers, protocols, frag_count, frag_offset, rtts, ult_rtts = analyze_traceroute(packets)
    generate_results(src, dst, routers, protocols, frag_count, frag_offset, rtts, ult_rtts)