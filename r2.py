
import struct


def parse_r2_pcap(filename):
    try:
        f = open(filename, "rb")
    except FileNotFoundError:
        return None
    global_hdr = f.read(24)
    if len(global_hdr) < 24:
        return None
    magic = struct.unpack("<I", global_hdr[:4])[0]
    is_nano = False
    if magic == 0xd4c3b2a1:
        endian = ">"
    elif magic == 0xa1b2c3d4:
        endian = "<"
    elif magic == 0x4d3cb2a1:
        endian = ">"
        is_nano = True
    elif magic == 0xa1b23c4d:
        endian = "<"
        is_nano = True
    else:
        return None

    header_format = endian + "IIII"
    ts_mult = 0.000000001 if is_nano else 0.000001

    src_node = None
    ttl_counts = {}
    probes_sent = {}
    hop_routers = {}
    ult_dest = None
    router_rtts = {}

    while True:
        p_hdr = f.read(16)
        if len(p_hdr) < 16:
            break
        ts_sec, ts_frac, incl_len, _ = struct.unpack(header_format, p_hdr)
        abs_time = ts_sec + (ts_frac * ts_mult)
        data = f.read(incl_len)

        if len(data) < 34:
            continue
        if struct.unpack(">H", data[12:14])[0] != 0x0800:
            continue
        ip = 14
        ihl = (data[ip] & 0x0F) * 4
        ttl = data[ip + 8]
        prot = data[ip+9]
        src_ip = ".".join(map(str, data[ip+12:ip+16]))
        dst_ip = ".".join(map(str, data[ip+16:ip+20]))
        payload = ip + ihl

        if src_node is None and prot in [1,17]:
            src_node = src_ip
        if src_ip == src_node:
            

            if prot == 17 and len(data) >= payload + 4:
                src_port = struct.unpack(">H", data[payload : payload+2])[0]
                if 33434 <= struct.unpack(">H", data[payload+2:payload+4])[0] <= 33529:
                    if src_port not in probes_sent:
                        probes_sent[src_port] = {'times': [], "ttl": ttl}
                    probes_sent[src_port]['times'].append(abs_time)
                    ult_dest = dst_ip
                    ttl_counts[ttl] = ttl_counts.get(ttl, 0) + 1

            elif prot == 1 and data[payload] == 8:
                seq = struct.unpack(">H", data[payload + 6: payload + 8])[0]
                if seq not in probes_sent:
                    probes_sent[seq] = {'times': [], 'ttl':ttl}
                probes_sent[seq]['times'].append(abs_time)
                ult_dest = dst_ip
                ttl_counts[ttl] = ttl_counts.get(ttl, 0) + 1 

        elif prot == 1 and dst_ip == src_node:
            icmp_type = data[payload]
            if icmp_type in [11, 0, 3]:
                router_ip = src_ip
                if router_ip not in router_rtts:
                    router_rtts[router_ip] = []
                orig_ip_start = payload + 8
                match_key = None
                if icmp_type == 0:
                    # Echo reply: sequence number is in this packet's own ICMP header
                    match_key = struct.unpack(">H", data[payload+6:payload+8])[0]
                elif len(data) >= orig_ip_start + 20:
                    # Type 11 / 3: original IP header is embedded after the 8-byte ICMP header
                    orig_ihl = (data[orig_ip_start] & 0x0F) * 4
                    orig_prot = data[orig_ip_start + 9]
                    orig_payload = orig_ip_start + orig_ihl
                    if orig_prot == 17:      # Linux: original UDP source port
                        match_key = struct.unpack(">H", data[orig_payload:orig_payload+2])[0]
                    elif orig_prot == 1:     # Windows: original ICMP echo sequence number
                        match_key = struct.unpack(">H", data[orig_payload+6:orig_payload+8])[0]

                if match_key is not None and match_key in probes_sent:
                    probe_info = probes_sent[match_key]
                    probe_ttl = probe_info['ttl']

                    if probe_ttl not in hop_routers and router_ip != ult_dest:
                        hop_routers[probe_ttl] = router_ip

                    for sent_time in probe_info['times']:
                        router_rtts[router_ip].append((abs_time - sent_time) * 1000)
                    del probes_sent[match_key]

    sorted_ttls = sorted(hop_routers.keys())
    router_sequence = [hop_routers[t] for t in sorted_ttls]

    hop_rtts = []
    for router in router_sequence:
        rtts = router_rtts.get(router, [])
        hop_rtts.append(sum(rtts) / len(rtts) if rtts else 0.0)

    return ttl_counts, router_sequence, hop_rtts

def print_tabular_format(group, file_list, results):

    col_w = 20

    print(f"{group} Number of probes for each TTL\n")

    header = f"{'TTL':<5}" + "".join([f"{name:<{col_w}}" for name in file_list])
    print(header)

    max_ttl = 0
    for res in results:
        if res and res[0]:
            max_ttl = max(max_ttl, max(res[0].keys()))

    for ttl in range(1, max_ttl + 1):
        row_str = f"{ttl:<5}"
        for res in results:
            if res:
                count = res[0].get(ttl, 0)
                row_str += f"{count:<{col_w}}"
            else:
                row_str += f"{"N/A":<{col_w}}"
        print(row_str)

    print("\n")

    print(f"{group} Intermediate Nodes\n")

    header = "".join([f'{name:<{col_w}}' for name in file_list])
    print(header)

    max_hops = max([len(res[1]) for res in results if res]) if results else 0

    for hop_idx in range(max_hops):
        row_str = ""
        for res in results:
            if res and hop_idx < len(res[1]):
                ip = res[1][hop_idx]
                row_str += f'{ip:<{col_w}}'
            else:
                row_str += f'{' ':<{col_w}}'
        print(row_str)

    print('\n')

    print(f"{group} Average RTT's\n")
    header = f"{'TTL':<5}" + "".join([f"{name:<{col_w}}" for name in file_list])
    print(header)

    for hop_idx in range(max_hops):
        row_str = f"{hop_idx + 1:<5}"
        for res in results:
            if res and hop_idx < len(res[2]):
                avg_rtt = res[2][hop_idx]
                rtt_str = f"{round(avg_rtt, 2)}ms"
                row_str += f"{rtt_str:<{col_w}}"
            else:
                row_str += f"{' ':<{col_w}}"
        print(row_str)

def analyze_r2_group(group_name, folder, file_list):
    results = [parse_r2_pcap(folder + f) for f in file_list]
    print_tabular_format(group_name, file_list, results)

if __name__ == "__main__":
    folder = "PcapTracesAssignment3/"
    group_1_files = ["group1-trace1.pcap", "group1-trace2.pcap", "group1-trace3.pcap", "group1-trace4.pcap", "group1-trace5.pcap"]
    group_2_files = ["group2-trace1.pcap", "group2-trace2.pcap", "group2-trace3.pcap", "group2-trace4.pcap", "group2-trace5.pcap",]

   
    analyze_r2_group("Group 1", folder, group_1_files)
    analyze_r2_group("Group 2", folder, group_2_files)