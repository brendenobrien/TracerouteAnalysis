import struct

class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>
    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = struct.unpack('BBBB',buffer1)
        dst_addr = struct.unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        result = struct.unpack('B', value)[0]
        length = (result & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)

    def get_protocol(self, buffer):
        self.protocol = struct.unpack('B', buffer)[0]

    def get_fragmentation_info(self, id_buffer, frag_buffer):
        self.identification = struct.unpack('>H', id_buffer)[0]
        frag_info = struct.unpack('>H', frag_buffer)[0]
        self.flags = frag_info >> 13
        self.flag_offset = (frag_info & 0x1FFF) * 8
 
class UDP_Header:
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0

    def get_ports(self, buffer):
        self.src_port = struct.unpack('>H', buffer[0:2])[0]
        self.dst_port = struct.unpack('>H', buffer[2:4])[0]

class ICMP_Header:
    def __init__(self):
        self.type = 0
        self.code = 0
        self.seq_num = 0

    def get_type_and_code(self, buffer):
        self.type, self.code = struct.unpack('BB', buffer[0:2])

    def get_sequence_num(self, buffer):
        self.seq_num = struct.unpack('>H', buffer[0:2])[0]

class packet:

    def __init__(self):
        self.IP_header = IP_Header()
        self.UDP_header = None
        self.ICMP_header = None
        self.timestamp = 0
        self.packet_No = 0

        self.is_probe = False
        self.is_error = False
        self.embedded_match_key = None
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = struct.unpack('I',buffer1)[0]
        microseconds = struct.unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)
