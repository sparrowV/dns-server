import sys
import socket
from struct import *
import random
import os
from easyzone import easyzone

ip = "127.0.0.1"
port = 5353
buffer_size = 2048

def name_to_bytes(name):
    name_parts = name.split(".")
    bytes = None
    for elem in name_parts:
        if(elem!=""):
            if(bytes == None):
                bytes = (len(elem)).to_bytes(1,byteorder="big")
                for ch in elem:
                    bytes+=(ord(ch)).to_bytes(1,byteorder="big")
            else:
                bytes+=(len(elem)).to_bytes(1,byteorder="big")
                for ch in elem:
                    bytes += (ord(ch)).to_bytes(1, byteorder="big")

    bytes+=(0).to_bytes(1,byteorder="big")

    return bytes

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

def get_name_index(question):
    i = 0
    domain_name = ""
    while (question[i] != 0):
        length = question[i]
        domain_name += question[i + 1:i + length + 1].decode("utf-8") + "."
        i += (length + 1)
    return i+1

def replace_id(id,header):
   return  (id).to_bytes(2, byteorder='big') + header[2:]

def replace_name(name,question):
    i =  get_name_index(question)
    query = (0).to_bytes(1, byteorder="big")
    name_parts = name.split(".")
    for part in name_parts:
        if (part != ""):
            length = (len(part)).to_bytes(1, byteorder='big')
            query += length
            #print(length)
            for ch in part:
                #print(hex(ord(ch)))
                query += (ord(ch)).to_bytes(1, byteorder='big')

            print("-------")
    query += (0).to_bytes(1, byteorder='big')
    query = query[1:]

    return query + question[i:]




def make_dns_question(name):
    id = random.randint(128, 65000)
    query = (id).to_bytes(2, byteorder='big')

    second_line = int('0b0000000100100000', 2).to_bytes(2, byteorder='big')
    query += second_line
    print(query)

    qdcount = (1).to_bytes(2, byteorder='big')
    query += qdcount
    ancount = (0).to_bytes(2, byteorder='big')

    query += ancount
    nscount = (0).to_bytes(2, byteorder='big')

    query += nscount
    arcount = (0).to_bytes(2, byteorder='big')

    query += arcount

    name_parts = name.split('.')
    print("----------")
    #print(query)
    for part in name_parts:
        if(part!=""):
            length = (len(part)).to_bytes(1, byteorder='big')
            query += length
            print(length)
            for ch in part:
                print(hex(ord(ch)))
                query += (ord(ch)).to_bytes(1, byteorder='big')

            print("-------")
    query += (0).to_bytes(1, byteorder='big')
    print("``````````````````````````````````")
    print(query)

    return query


def parse_name(text,entire_responce):
    i = 0
    j = i
    contains_pointer = False
    domain_name = ""
    #print("text[i] ",text[0])
    while (text[i] != 0):

        length = text[i]
        if (length > 64):
            pointer = unpack("!H", text[i:i + 2])

            # 2 bytes for pointer and plus one for new guy
            if(not contains_pointer):
              j =i + 2

            contains_pointer = True
           # print("here we have",text[j:j+2])
           # print("j in here ->",j)
            i = pointer[0] & 0b0011111111111111
            #print(hex(i))
            #print("here")
            text = entire_responce
            continue
        domain_name += text[i + 1:i + length + 1].decode("utf-8") + "."
        i += (length + 1)

    #if it contains pointer we should return j as number of bytes
    if(contains_pointer):
        #print("j is ",j)
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

    #print("pointer hex = ",answer[i:i+2])
    pointer = unpack("!H", answer[i:i + 2])
    i += 2
    pointer = pointer[0] & 0b0011111111111111
    #print("pointer = ", pointer)

    #we don't need j
    tld_name,j = parse_name(whole_responce[pointer:],whole_responce)

    fields["tld_name"] = tld_name



    fields["qtype"] = int.from_bytes(answer[i:i + 2], byteorder="big")
    i += 2

    #aaaa record n# = 28
    if(fields["qtype"] >1 and fields["qtype"]!=28):
        in_additional = False

    fields["qclass"] = int.from_bytes(answer[i:i + 2], byteorder="big")
    i += 2

    ttl = unpack("!i", answer[i: i + 4])
    fields["ttl"] = ttl[0]
    i += 4
    #print("ttl",ttl)

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
     #       print("rdlength = ",fields["rdlength"])
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
    #print(answer_count,ns_count,additional_source_count)
    #print("answer is -> ", answer)
    i = 0
    answer_query_fields,j = parse_dns_answer_query_section(answer)
    i+=j
    print(answer_query_fields)

    if(answer_count > 0):
       answer_fields,j = parse_dns_answer2(answer[i:],whole_responce,True)
       i+=j
      # print("answer foundhere \n\n\n\n")
       if("ip" in answer_fields.keys()):
           return answer_fields,1


       return [answer_fields],-1
    name_servers = []
    for ns_counter in range(ns_count):

        ns_fields,j = parse_dns_answer2(answer[i:],whole_responce,False)
        name_servers.append(ns_fields)
        i+=j

       # print("ns_fields",ns_fields)

    #print("additional resource\n\n\n\n\n")
    ar_list = []
    for ar_counter in range(additional_source_count-1):
        try:
           # print("in addional",answer[i:i + 6])
            ar_fields, j = parse_dns_answer2(answer[i:], whole_responce, True)
            ar_list.append(ar_fields)
            i += j
            #print(answer[i:i + 3])
            #print("ns_fields", ar_fields)
        except:
            i+=11

    merge_ns_and_ar(name_servers,ar_list)
   # print("merged\n\n\n\n")
    #print(name_servers)

    return name_servers,0

def ip_to_bytes(ip_string):
    ip_parts = ip_string.split(".")
    bytes = None
    for elem in ip_parts:
        if(bytes == None):
            bytes = (int(elem)).to_bytes(1,byteorder="big")
        else:
            bytes+=(int(elem)).to_bytes(1,byteorder="big")

    return bytes

def build_responce_A(original_query,cname_info,domain_name):
    name_query_first_part = original_query[:2]
    #print("sd", name_query_first_part)
    # change to responce
    second_line = int('0b1000000110000000', 2).to_bytes(2, byteorder='big')
    #print("second line", second_line[0])

    name_query_first_part += second_line
    #print("ans h", name_query_first_part)
    qdcount = (1).to_bytes(2, byteorder='big')

    name_query_first_part += qdcount

    # answer count
    name_query_first_part += (1).to_bytes(2, byteorder="big")

    # atuhority
    name_query_first_part += (0).to_bytes(2, byteorder="big")

    # addtional
    name_query_first_part += (0).to_bytes(2, byteorder="big")

    domain_parts = domain_name.split(".")
    domain_length_bytes = 0

    for elem in domain_parts:
        domain_length_bytes += len(elem) + 1

    # for null terminator
    domain_length_bytes += 1

    name_query_first_part += original_query[12:12 + domain_length_bytes - 1 + 4]
    #print("before answer \n\n\n\n\n\n", name_query_first_part)

    # pointer
    new_query_second_part = int('0b1100000000001100', 2).to_bytes(2, byteorder='big')
    # new_query_second_part = name_to_bytes(domain_name)

    new_query_second_part += (1).to_bytes(2, byteorder="big")
    new_query_second_part += (1).to_bytes(2, byteorder="big")

    new_query_second_part += (cname_info["ttl"]).to_bytes(4, byteorder="big")

    #ip length
    new_query_second_part += (4).to_bytes(2, byteorder="big")

    new_query_second_part += ip_to_bytes(cname_info["ip"])



    return name_query_first_part+ new_query_second_part


def build_responce_cname(original_query,cname_info,domain_name,data_from_root):
    name_query_first_part = original_query[:2]
    #print("sd",name_query_first_part)
    #change to responce
    second_line = int('0b1000000110000000', 2).to_bytes(2, byteorder='big')
    #print("second line",second_line[0])

    name_query_first_part+=second_line
    #print("ans h",name_query_first_part)
    qdcount = (1).to_bytes(2, byteorder='big')

    name_query_first_part+=qdcount


    #answer count
    name_query_first_part+=(2).to_bytes(2,byteorder="big")

    #atuhority
    name_query_first_part+=(0).to_bytes(2,byteorder="big")

    #addtional
    name_query_first_part+=(0).to_bytes(2,byteorder="big")




    domain_parts = domain_name.split(".")
    domain_length_bytes = 0

    for elem in domain_parts:
        domain_length_bytes+=len(elem) +1


    #for null terminator
    domain_length_bytes+=1

    name_query_first_part += original_query[12:12+domain_length_bytes-1+4]
    #print("before answer \n\n\n\n\n\n",name_query_first_part)

    #pointer
    new_query_second_part = int('0b1100000000001100', 2).to_bytes(2, byteorder='big')
   # new_query_second_part = name_to_bytes(domain_name)

    new_query_second_part+=(5).to_bytes(2,byteorder="big")
    new_query_second_part+=(1).to_bytes(2,byteorder="big")
    new_query_second_part+=(cname_info["ttl"]).to_bytes(4,byteorder="big")

    #data_length
    cname_bytes = name_to_bytes(cname_info["tld_name"])
    new_query_second_part+=(len(cname_bytes)).to_bytes(2,byteorder="big")

    pointer_for_second = (len(name_query_first_part+new_query_second_part) | 0b1100000000000000) .to_bytes(2,byteorder="big")
    #print("pointer second",bytes(pointer_for_second))
    #print(bin(len(name_query_first_part+new_query_second_part)-1 | 0b1100000000000000))
    #name_itself
    new_query_second_part+=cname_bytes

    #------------------------------------------------------------------------
    #cnmae info
    #new_query_second_part+=cname_bytes
    new_query_second_part+=pointer_for_second
    #print("here nas\n\n\n",new_query_second_part)
    new_query_second_part+=(1).to_bytes(2,byteorder="big") #type
    new_query_second_part+=(1).to_bytes(2,byteorder="big") #class

    new_query_second_part+=(cname_info["ttl"]).to_bytes(4,byteorder="big")
    new_query_second_part+=(4).to_bytes(2,byteorder="big")

    #ip to bytes
    new_query_second_part+=ip_to_bytes(cname_info["ip"])

    full_recponse = name_query_first_part + new_query_second_part
    #print(full_recponse)

    return full_recponse









def iterative_query(query_original,sock,address_original,name_original,id_original):

    sock_client_root = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_client_root.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    addr_root = ("192.33.4.12", 53)
    sent = sock_client_root.sendto(query_original, addr_root)
    print("sending to root \n")
    data_from_root, address_root = sock_client_root.recvfrom(buffer_size)

    query_original_copy = query_original
    data_in_shorts_root = unpack("!1H2B4H", data_from_root[0:12])
    header_root = parse_dns_header(data_in_shorts_root)


   # sock.sendto(data_from_root, address_original)

    ans = header_root["ancount"]


    name_servers = None


    last_ip = 0
    cname = False
    while(True):


         name_servers,res = parse_dns_answer(data_from_root[12:], header_root["ancount"], header_root["nscount"], header_root["arcount"],
                         data_from_root)

         print("name_servers \n",name_servers)
         if(res == 1):
             break

         if(res == -1):
            #print("cname here\n\n",name_servers[0]["ns_name"])
            cname = True
            new_query = query_original[:12] +   replace_name(name_servers[0]["ns_name"],query_original[12:])
            query_original = new_query
           # print(new_query)
            ip = last_ip
         else:

            ip = name_servers[0]["ip"]
         last_ip = ip

         addr_root = (ip, 53)
         sent = sock_client_root.sendto(query_original, addr_root)
         data_from_root, address_root = sock_client_root.recvfrom(buffer_size)
         data_in_shorts_root = unpack("!1H2B4H", data_from_root[0:12])
         header_root = parse_dns_header(data_in_shorts_root)
         ans = header_root["ancount"]
       #  sock.sendto(data_from_root, address_original)

    if(cname):
      print("needed cname\n",name_servers)
      resp = build_responce_cname(query_original_copy,name_servers,name_original,data_from_root)

      sock.sendto(resp, address_original)
    else:
      print("A record\n")
      sock.sendto(data_from_root, address_original)


    #returns dictionary
def parse_dns_header(header_in_shorts):
    fields = {}


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





def run_dns_server(configpath):
    # your code here
    #print(configpath)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((ip,port))
    print("Listening on UDP {}:{}".format(*sock.getsockname()))


    while True:
        query_original, address_original = sock.recvfrom(buffer_size)






        query_original_in_shorts = unpack("!1H2B4H", query_original[0:12])

        header_fields =  parse_dns_header(query_original_in_shorts)

        fields =parse_dns_question(query_original[12:])
        name = fields["domain_name"]
        exists = os.path.isfile('./zone_files/'+name+"conf")
        if(exists):
            zone = easyzone.zone_from_file(name,'./zone_files/'+name+"conf")
            ips = zone.names[name].records('A').items
            #p = zone.names["www."].items
            info = {"ttl":zone.names[name].ttl,"ip":ips[0]}

            print("file is in the zone\n")

            resp = build_responce_A(query_original,info,name)
            sock.sendto(resp,address_original)

        else:
         print("start iterative search\n")
         iterative_query(query_original,sock,address_original,fields["domain_name"],header_fields["id"])
       # sock.sendto(data_from_root, address_original)
# do not change!
if __name__ == '__main__':
    configpath = sys.argv[1]

    run_dns_server(configpath)
    run_dns_server(configpath)