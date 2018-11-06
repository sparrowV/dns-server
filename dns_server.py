import sys
import socket
from struct import *

ip = "127.0.0.1"
port = 53
buffer_size = 512

def parse_dns_question(question):
    fields = {}

    print("question is -> ",question)
    i = 0
    domain_name = ""
    while(question[i] !=0):
        length = question[i]
        domain_name+=question[i+1:i+length+1].decode("utf-8") + "."
        i+=(length+1)

    print("doman name = ", domain_name)
    fields["domain_name"] = domain_name
    #for null terminator at the end of domain name
    i+=1

    fields["qtype"] = int.from_bytes(question[i:i+2],byteorder="big")
    i+=2
    fields["qclass"] = int.from_bytes(question[i:i+2],byteorder="big")

    print(fields)
    return fields







#returns dictionary
def parse_dns_header(header_in_shorts):
    fields = {}


    fields["id"] = header_in_shorts[0]
    fields["qr"] = header_in_shorts[1] & 0b10000000
    fields["opcode"] = header_in_shorts[1]>>3 - fields["qr"] * 2**5
    fields["aa"] = header_in_shorts[1] &0b00000100
    fields['tc'] = header_in_shorts[1] & 0b00000010
    fields["rd"] = header_in_shorts[1] & 0b00000001

    fields["ra"] = header_in_shorts[2] &  0b10000000

    #reserved for future, is 0
    fields["z"] = 0
    fields["rcode"] = header_in_shorts[2] & 0b00001111

    fields["qdcount"] = header_in_shorts[3]
    fields["ancount"] = header_in_shorts[4]
    fields["nscount"] = header_in_shorts[5]
    fields["arcount"] = header_in_shorts[6]

    print(fields)
    return fields





def run_dns_server(configpath = None):
    # your code here
    #print(configpath)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip,port))
    print("Listening on UDP {}:{}".format(*sock.getsockname()))


    while True:
        data, address = sock.recvfrom(buffer_size)
        print(address)
        print("received data",data)


        print(int.from_bytes(data[0:2],byteorder="big"))
        data_in_shorts = unpack("!1H2B4H",data[0:12])
        print(data_in_shorts)
      #  parse_dns_header(data_in_shorts)
       # parse_dns_question((data[12:]))

        sock_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock_client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        addr = ("198.41.0.4",53)
        sent = sock_client.sendto(data, addr)
        data2, address2 = sock_client.recvfrom(buffer_size)
        sock.sendto(data2,address)






# do not change!
if __name__ == '__main__':
    #configpath = sys.argv[1]
    configpath = "sd"
    run_dns_server()
    #run_dns_server(configpath)