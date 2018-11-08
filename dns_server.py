import sys
import socket
from struct import *

ip = "127.0.0.1"
port = 53
buffer_size = 2048

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


def parse_name(text,entire_responce):
    i = 0
    j = i
    contains_pointer = False
    domain_name = ""
    print("text[i] ",text[0])
    while (text[i] != 0):

        length = text[i]
        if (length > 64):
            pointer = unpack("!H", text[i:i + 2])

            # 2 bytes for pointer and plus one for new guy
            if(not contains_pointer):
              j =i + 2

            contains_pointer = True
            print("here we have",text[j:j+2])
            print("j in here ->",j)
            i = pointer[0] & 0b0011111111111111
            #print(hex(i))
            print("here")
            text = entire_responce
            continue
        domain_name += text[i + 1:i + length + 1].decode("utf-8") + "."
        i += (length + 1)

    #if it contains pointer we should return j as number of bytes
    if(contains_pointer):
        print("j is ",j)
        i = j

    if(not contains_pointer):
        #for null terminator
        i+=1

    return domain_name,i

def parse_dns_answer_query_section(answer):
    fields = {}
    i = 0
    domain_name = ""
    while (answer[i] != 0):
        length = answer[i]

        domain_name += answer[i + 1:i + length + 1].decode("utf-8") + "."
        i += (length + 1)

    fields["domain_name"] = domain_name

    # for null terminator at the end of domain name
    i += 1

    fields["qtype"] = int.from_bytes(answer[i:i + 2], byteorder="big")
    i += 2
    fields["qclass"] = int.from_bytes(answer[i:i + 2], byteorder="big")
    i += 2

    return fields,i


def parse_dns_answer2(answer,whole_responce,in_additional):
    fields = {}

    i = 0

    print("pointer hex = ",answer[i:i+2])
    pointer = unpack("!H", answer[i:i + 2])
    i += 2
    pointer = pointer[0] & 0b0011111111111111
    print("pointer = ", pointer)

    #we don't need j
    tld_name,j = parse_name(whole_responce[pointer:],whole_responce)

    fields["tld_name"] = tld_name



    fields["qtype"] = int.from_bytes(answer[i:i + 2], byteorder="big")
    i += 2
    fields["qclass"] = int.from_bytes(answer[i:i + 2], byteorder="big")
    i += 2

    ttl = unpack("!i", answer[i: i + 4])
    fields["ttl"] = ttl[0]
    i += 4
    print("ttl",ttl)

    # rdlength unsigned short
    rdlength = unpack("!H", answer[i:i + 2])
    i += 2
    fields["rdlength"] = rdlength[0]
    if (in_additional):

        if(fields["qtype"] == 1):
            # ip
            ip = unpack("!4c", answer[i:i + 4])
            i+=4
            fields["ip"] = str(ord(ip[0])) + "." + str(ord(ip[1])) + "." + str(ord(ip[2])) + "." + str(ord(ip[3]))
        else:
            i+=fields["rdlength"]
    else:


        ns_name, j = parse_name(answer[i:],whole_responce)
        i+=j
        fields["ns_name"] = ns_name

    return fields,i


def merge_ns_and_ar(name_servers, ar_list):
    for name_server in name_servers:
        name = name_server["ns_name"]
        for additional_record in ar_list:
            ar_name = additional_record["tld_name"]
            if(name == ar_name and additional_record["qtype"] == 1):
                name_server["ip"] = additional_record["ip"]


def parse_dns_answer(answer,answer_count,ns_count,additional_source_count,whole_responce):

    fields = {}
    print(answer_count,ns_count,additional_source_count)
    print("answer is -> ", answer)
    i = 0
    answer_query_fields,j = parse_dns_answer_query_section(answer)
    i+=j
    print(answer_query_fields)


    name_servers = []
    for ns_counter in range(ns_count):
        ns_fields,j = parse_dns_answer2(answer[i:],whole_responce,False)
        name_servers.append(ns_fields)
        i+=j
        print(answer[i:i+3])
        print("ns_fields",ns_fields)

    print("additional resource\n\n\n\n\n")
    ar_list = []
    for ar_counter in range(additional_source_count-1):
        ar_fields, j = parse_dns_answer2(answer[i:], whole_responce, True)
        ar_list.append(ar_fields)
        i += j
        print(answer[i:i + 3])
        print("ns_fields", ar_fields)

    merge_ns_and_ar(name_servers,ar_list)
    print("merged\n\n\n\n")
    print(name_servers)

    return name_servers


def iterative_query(query_original,sock,address_original):
    sock_client_root = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_client_root.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    addr_root = ("192.33.4.12", 53)
    sent = sock_client_root.sendto(query_original, addr_root)
    data_from_root, address_root = sock_client_root.recvfrom(buffer_size)


    data_in_shorts_root = unpack("!1H2B4H", data_from_root[0:12])
    header_root = parse_dns_header(data_in_shorts_root)

   # sock.sendto(data_from_root, address_original)

    ans = header_root["ancount"]
    print("ans ->\n\n\n",ans)

    name_servers = None
    c = 0
    while(ans==0):

         if (c == 1):
            print("sd")
         name_servers = parse_dns_answer(data_from_root[12:], header_root["ancount"], header_root["nscount"], header_root["arcount"],
                         data_from_root)
         ip = name_servers[0]["ip"]

         addr_root = (ip, 53)
         sent = sock_client_root.sendto(query_original, addr_root)
         data_from_root, address_root = sock_client_root.recvfrom(buffer_size)
         data_in_shorts_root = unpack("!1H2B4H", data_from_root[0:12])
         header_root = parse_dns_header(data_in_shorts_root)
         ans = header_root["ancount"]
        # sock.sendto(data_from_root, address_original)
         c+=1


    print("here\n\n\n\n\n\n\n\n\n\n")
    ip = name_servers[0]["ip"]
    print("ip name server google ",ip)
    addr_root = (ip, 53)
    sent = sock_client_root.sendto(query_original, addr_root)
    data_from_root, address_root = sock_client_root.recvfrom(buffer_size)
    data_in_shorts_root = unpack("!1H2B4H", data_from_root[0:12])
    header_root = parse_dns_header(data_in_shorts_root)

    i = 12
    answer_query_fields, j = parse_dns_answer_query_section(data_from_root[12:])
    i += j
    name_servers = parse_dns_answer2(data_from_root[i:], data_from_root,True)

    sock.sendto(data_from_root, address_original)
    print("answern\n\n",name_servers)

    #returns dictionary
def parse_dns_header(header_in_shorts):
    fields = {}

    """
          fields["opcode"] = (header_in_shorts[1]>>3) - fields["qr"] * 32
    fields["aa"] = header_in_shorts[1] &0b00000100
    fields['tc'] = header_in_shorts[1] & 0b00000010
    fields["rd"] = header_in_shorts[1] & 0b00000001

    fields["ra"] = header_in_shorts[2] &  0b10000000
    """

    print(header_in_shorts)
    fields["id"] = header_in_shorts[0]

    fields["qr"] = header_in_shorts[1] >>7
    print(bin(header_in_shorts[1]>>3))
    print("qr = ",fields["qr"])
    fields["opcode"] = (header_in_shorts[1]>>3) - fields["qr"] * 16
    fields["aa"] = (header_in_shorts[1] &0b00000100) >>2
    fields['tc'] = (header_in_shorts[1] & 0b00000010)>>1
    fields["rd"] = header_in_shorts[1] & 0b00000001

    fields["ra"] = header_in_shorts[2] >>7

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
        query_original, address_original = sock.recvfrom(buffer_size)

        print("received data",query_original)



        query_original_in_shorts = unpack("!1H2B4H", query_original[0:12])

        parse_dns_header(query_original_in_shorts)
        iterative_query(query_original,sock,address_original)
       # sock.sendto(data_from_root, address_original)





      #  print(data2)







# do not change!
if __name__ == '__main__':
    #configpath = sys.argv[1]
    configpath = "sd"
    run_dns_server()
    #run_dns_server(configpath)