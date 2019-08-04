# #!/usr/bin/env python3
# # (c) 2014 Patryk Hes
# import socketserver
# import sys
#
# DNS_HEADER_LENGTH = 12
# # TODO make some DNS database with IPs connected to regexs
# IP = '192.168.1.1'
#
#
# class DNSHandler(socketserver.BaseRequestHandler):
#     def handle(self):
#         socket = self.request[1]
#         data = self.request[0].strip()
#
#         # If request doesn't even contain full header, don't respond.
#         if len(data) < DNS_HEADER_LENGTH:
#             return
#
#         # Try to read questions - if they're invalid, don't respond.
#         try:
#             all_questions = self.dns_extract_questions(data)
#         except IndexError:
#             return
#
#         # Filter only those questions, which have QTYPE=A and QCLASS=IN
#         # TODO this is very limiting, remove QTYPE filter in future, handle different QTYPEs
#         accepted_questions = []
#         for question in all_questions:
#             name = str(b'.'.join(question['name']), encoding='UTF-8')
#             if question['qtype'] == b'\x00\x01' and question['qclass'] == b'\x00\x01':
#                 accepted_questions.append(question)
#                 print('\033[32m{}\033[39m'.format(name))
#             else:
#                 print('\033[31m{}\033[39m'.format(name))
#
#         response = (
#             self.dns_response_header(data) +
#             self.dns_response_questions(accepted_questions) +
#             self.dns_response_answers(accepted_questions)
#         )
#         socket.sendto(response, self.client_address)
#
#     def dns_extract_questions(self, data):
#         """
#         Extracts question section from DNS request data.
#         See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
#         """
#         questions = []
#         # Get number of questions from header's QDCOUNT
#         n = (data[4] << 8) + data[5]
#         # Where we actually read in data? Start at beginning of question sections.
#         pointer = DNS_HEADER_LENGTH
#         # Read each question section
#         for i in range(n):
#             question = {
#                 'name': [],
#                 'qtype': '',
#                 'qclass': '',
#             }
#             length = data[pointer]
#             # Read each label from QNAME part
#             while length != 0:
#                 start = pointer + 1
#                 end = pointer + length + 1
#                 question['name'].append(data[start:end])
#                 pointer += length + 1
#                 length = data[pointer]
#             # Read QTYPE
#             question['qtype'] = data[pointer+1:pointer+3]
#             # Read QCLASS
#             question['qclass'] = data[pointer+3:pointer+5]
#             # Move pointer 5 octets further (zero length octet, QTYPE, QNAME)
#             pointer += 5
#             questions.append(question)
#         return questions
#
#     def dns_response_header(self, data):
#         """
#         Generates DNS response header.
#         See http://tools.ietf.org/html/rfc1035 4.1.1. Header section format.
#         """
#         header = b''
#         # ID - copy it from request
#         header += data[:2]
#         # QR     1    response
#         # OPCODE 0000 standard query
#         # AA     0    not authoritative
#         # TC     0    not truncated
#         # RD     0    recursion not desired
#         # RA     0    recursion not available
#         # Z      000  unused
#         # RCODE  0000 no error condition
#         header += b'\x80\x00'
#         # QDCOUNT - question entries count, set to QDCOUNT from request
#         header += data[4:6]
#         # ANCOUNT - answer records count, set to QDCOUNT from request
#         header += data[4:6]
#         # NSCOUNT - authority records count, set to 0
#         header += b'\x00\x00'
#         # ARCOUNT - additional records count, set to 0
#         header += b'\x00\x00'
#         return header
#
#     def dns_response_questions(self, questions):
#         """
#         Generates DNS response questions.
#         See http://tools.ietf.org/html/rfc1035 4.1.2. Question section format.
#         """
#         sections = b''
#         for question in questions:
#             section = b''
#             for label in question['name']:
#                 # Length octet
#                 section += bytes([len(label)])
#                 section += label
#             # Zero length octet
#             section += b'\x00'
#             section += question['qtype']
#             section += question['qclass']
#             sections += section
#         return sections
#
#     def dns_response_answers(self, questions):
#         """
#         Generates DNS response answers.
#         See http://tools.ietf.org/html/rfc1035 4.1.3. Resource record format.
#         """
#         records = b''
#         for question in questions:
#             record = b''
#             for label in question['name']:
#                 # Length octet
#                 record += bytes([len(label)])
#                 record += label
#             # Zero length octet
#             record += b'\x00'
#             # TYPE - just copy QTYPE
#             # TODO QTYPE values set is superset of TYPE values set, handle different QTYPEs, see RFC 1035 3.2.3.
#             record += question['qtype']
#             # CLASS - just copy QCLASS
#             # TODO QCLASS values set is superset of CLASS values set, handle at least * QCLASS, see RFC 1035 3.2.5.
#             record += question['qclass']
#             # TTL - 32 bit unsigned integer. Set to 0 to inform, that response
#             # should not be cached.
#             record += b'\x00\x00\x00\x00'
#             # RDLENGTH - 16 bit unsigned integer, length of RDATA field.
#             # In case of QTYPE=A and QCLASS=IN, RDLENGTH=4.
#             record += b'\x00\x04'
#             # RDATA - in case of QTYPE=A and QCLASS=IN, it's IPv4 address.
#             record += b''.join(map(
#                 lambda x: bytes([int(x)]),
#                 IP.split('.')
#             ))
#             records += record
#         return records
#
# if __name__ == '__main__':
#     # Minimal configuration - allow to pass IP in configuration
#     if len(sys.argv) > 1:
#         IP = sys.argv[1]
#     host, port = '', 53
#     server = socketserver.ThreadingUDPServer((host, port), DNSHandler)
#     print('\033[36mStarted DNS server.\033[39m')
#     try:
#         server.serve_forever()
#     except KeyboardInterrupt:
#         server.shutdown()
#         sys.exit(0)


######################################################################

# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

import argparse
import socket

from dnslib import DNSRecord, RR, A

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process input')
    parser.add_argument("--ip", help="set listen ip address", action="store", type=str, default="192.168.57.1")
    parser.add_argument("--port", help="set listen port", action="store", type=int, default=53)
    parser.add_argument("--withInternet", help="enable real resolving", action="store_true")
    parser.add_argument("--debug", help="enable debug logging", action="store_true")
    args = parser.parse_args()

    if args.debug:
        print('IP: %s Port: %s withInternet: %s' % (args.ip, args.port, args.withInternet))

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((args.ip, args.port))

    try:
        while True:
            data, addr = udp_sock.recvfrom(1024)
            print(data)
            d = DNSRecord.parse(data)
            for question in d.questions:
                qdom = question.get_qname()
                r = d.reply()
                if args.withInternet:
                    try:
                        realip = socket.gethostbyname(qdom.idna())
                    except Exception as e:
                        if args.debug:
                            print(e)
                        realip = args.ip
                    r.add_answer(RR(qdom, rdata=A(realip), ttl=60))
                    if args.debug:
                        print("Request: %s --> %s" % (qdom.idna(), realip))
                else:
                    r.add_answer(RR(qdom, rdata=A(args.ip), ttl=60))
                    if args.debug:
                        print("Request: %s --> %s" % (qdom.idna(), args.ip))
                udp_sock.sendto(r.pack(), addr)
    except KeyboardInterrupt:
        if args.debug:
            print("done.")
    udp_sock.close()
