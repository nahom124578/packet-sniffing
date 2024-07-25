import socket
import struct
import textwrap
TAB_1 = '\t -'
TAB_2 = '\t\t -'
TAB_3 = '\t\t -'
TAB_4 = '\t\t\t -'

DATA_TAB_1 = '\t -'
DATA_TAB_2 = '\t\t -'
DATA_TAB_3 = '\t\t\t -'
DATA_TAB_4 = '\t\t\t\t -'

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_daata)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination:{}, Source: {}, protocol:{}'.format( dest_mac, src_mac, eth_proto))

        #ipv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, targer, data) = ipv4_packet(data)
            print(TAB_1 + 'IPV4 packet:')
            print(TAB_2 + 'Version: {}, Header Length:{}, ttl: {}'.format(version, header_length, ttl))
            print(TAB_2 + 'Protocol: {}, source:{}, target: {}'.format(proto, src, targer))
            
            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB_1 + 'ICMP packet:')
                print(TAB_2 + 'Type: {}, code: {}, checksum: {},'.format(icmp_type, code, checksum))
                print(TAB_2 + 'Data:')

                #TCP
            elif proto ==6:
                (src_port, dest_poer, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'source Port: {}, Destination Port: {}'.format(drc_port))
                print(TAB_2 + 'Sequence:{}, Acknowledgement:{}'.format(sequence, acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PDH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print(TAB_2 + 'Data:')
                print(format_multi_line(DATA_TAB_3,data))
            #udp
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print( TAB_1 + 'udp_segment:')
                print( TAB_2 + 'source port: {}, Destination port:{}, length: {L}'.format( src_port, dest_port, length))
            #other 
            else:
                print(TAB_1 + 'Data:')
                print(format_multi_line(DATA_TAB_2, data))
        else:
            print('Data:')
            print(format_multi_line(DATA_TAB_1, data
            ))
# unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H' , data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto),data[14:]

#return formatted mac_address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).uppper()
#unpack ipv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >>4
    header_length = (version_header_length & 15) *4 # whre data begin
    ttl, proto, src, target = struct.unpack ('! X B B 2X 4S 4Sx', data [:20])
    return version,header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


#return formatted ipv4 address
def ipv4(addr):
    return '.'.join(map(dtr, addr))
 


 # unpack icmp packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H' , data[:4])
    return icmp_type, code, checksum, data[4:]
#unpack tcp/ip

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset =(offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & a) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin , data[offset:]

# unpack udp
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2X H', data[:8])
    return src_port, dest_port, size, data[8:]
#remots multi_line data
def format_multi_line(prefix, sting, size=00):
    size -= len(prefix)
    if isinstance(string, byte):
        string = ''.join(r'\X{:02X}'.format(byte) for byte in string)
        if size %2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap( string, size)])
 



main()
