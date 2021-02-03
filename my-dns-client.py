# Written for the first programming project of CS455-001 at GMU Fall 2020
# John Delaney

from socket import *
import sys
import random
import struct
import time
import signal

lookupHostName = sys.argv[1] # A string of our hostname to translate into our QNAME

class header():
    def __init__(self):
        self.id = random.randint(0, 65535)
        self.qr = 0
        self.opcode = 0
        self.aa = 0
        self.tc = 0
        self.rd = 1
        self.ra = 0
        self.z = 0
        self.rcode = 0
        self.qdcount = 1
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0

class question():
    def __init__(self):
        self.qname = ""
        self.qnamelength = []
        self.qtype = 1
        self.qclass = 0x0001 # IN QClass

class answer():
    def __init__(self):
        self.name = None
        self.type = None
        self.aclass = None
        self.ttl = None
        self.rdlength = None
        self.rdata = []
        self.rdataindex = 0
def resend(signum, frame):
    raise Exception()

queryheader = header()
queryquestion = question()

print("Preparing DNS query..")

message = 0
message = message << 16

message = message | queryheader.id # 16-bit ID
bytelength = 2

message = message << 1 # QR = 0 (This is a query)

message = message << 4 # Opcode = 0 (This is a standard query)

message = message << 1 # AA = 0

message = message << 1 # TC = 0

message = message << 1 # RD
message = message | queryheader.rd # RD = 1

message = message << 1 # RA = 0

message = message << 3 # Z = 0

message = message << 4 # RCODE = 0
bytelength += 2

message = message << 16 # QDCOUNT
message = message | queryheader.qdcount # QDCOUNT = 1
bytelength += 2

message = message << 16 # ANCOUNT = 0
bytelength += 2

message = message << 16 # NSCOUNT = 0
bytelength += 2

message = message << 16 # ARCOUNT = 0
bytelength += 2

labels = lookupHostName.split(".") # QNAME
for label in labels:
    message = message << 8 # length octet
    message = message | len(label)
    queryquestion.qnamelength.insert(0, len(label))
    bytelength += 1

    for char in label: # add octets for each char in the label
        s = char.encode('utf-8')
        message = message << 8
        message = message | int("0x"+s.hex(), 0)
        bytelength += 1

message = message << 8 # QNAME is terminated by a 0 length octet
bytelength += 1

message = message << 16
message = message | queryquestion.qtype # QTYPE-- We set it to 1 because we are only interested in A type requests
bytelength += 2

message = message << 16
message = message | queryquestion.qclass
bytelength += 2

message = message.to_bytes(bytelength, byteorder = "big")

signal.signal(signal.SIGALRM, resend)

serverName = '8.8.8.8'
# Uncomment the following line to test the resend feature!
#serverName = '10.255.255.1'
serverPort = 53
attempt = 0
responseFound = False

while attempt < 3:
    attempt += 1
    print("Contacting DNS server..")
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    print("Sending DNS query..")
    clientSocket.sendto(message, (serverName, serverPort))
    signal.alarm(5)
    try:
        modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
    except:
        continue
    print("DNS response recieved (attempt "+str(attempt)+" of 3)")
    responseFound = True
    attempt = 3
    clientSocket.close()

if not responseFound:
    print("No DNS response recieved after 3 attempts! (╯°□°）╯︵ ┻━┻")
    quit()

print("Processing DNS response..")

messageInt = 0
messageInt = messageInt.from_bytes(modifiedMessage, byteorder = "big")

responseHeader = header()
responseQuestion = question()
responseAnswer = answer()

responseAnswer.rdata.insert(0, messageInt & 0xFF) # Still breaks when rdlength != 4
messageInt = messageInt >> 8
responseAnswer.rdata.insert(0, messageInt & 0xFF)
messageInt = messageInt >> 8
responseAnswer.rdata.insert(0, messageInt & 0xFF)
messageInt = messageInt >> 8
responseAnswer.rdata.insert(0, messageInt & 0xFF)
messageInt = messageInt >> 8

responseAnswer.rdlength = messageInt & 0xFFFF
messageInt = messageInt >> 16

responseAnswer.ttl = messageInt & 0xFFFFFFFF
messageInt = messageInt >> 32

responseAnswer.aclass = messageInt & 0xFFFF
messageInt = messageInt >> 16

responseAnswer.type = messageInt & 0xFFFF
messageInt = messageInt >> 16

responseAnswer.name = messageInt & 0xFFFF
messageInt = messageInt >> 16

responseQuestion.qclass = messageInt & 0xFFFF
messageInt = messageInt >> 16

responseQuestion.qtype = messageInt & 0xFFFF
messageInt = messageInt >> 16

messageInt = messageInt >> 8

len = len(queryquestion.qnamelength)
str = ""
for i in range(0, len):
    datanum = 0
    for j in range(0, queryquestion.qnamelength.pop(0)):
        datanum = messageInt & 0xFF
        messageInt = messageInt >> 8
        str += chr(datanum)
    string = messageInt & datanum
    if(i < len-1):
        messageInt = messageInt >> 8
        str += "."
messageInt = messageInt >> 8
str = str[::-1]
responseQuestion.qname = str

responseHeader.arcount = messageInt & 0xFFFF
messageInt = messageInt >> 16

responseHeader.nscount = messageInt & 0xFFFF
messageInt = messageInt >> 16

responseHeader.ancount = messageInt & 0xFFFF
messageInt = messageInt >> 16

responseHeader.qdcount = messageInt & 0xFFFF
messageInt = messageInt >> 16

responseHeader.rcode = messageInt & 0xF
messageInt = messageInt >> 4

responseHeader.z = messageInt & 0x7
messageInt = messageInt >> 3

responseHeader.ra = messageInt & 0x1
messageInt = messageInt >> 1

responseHeader.rd = messageInt & 0x1
messageInt = messageInt >> 1

responseHeader.tc = messageInt & 0x1
messageInt = messageInt >> 1

responseHeader.aa = messageInt & 0x1
messageInt = messageInt >> 1

responseHeader.opcode = messageInt & 0xF
messageInt = messageInt >> 4

responseHeader.qr = messageInt & 0x1
messageInt = messageInt >> 1

responseHeader.id = messageInt & 0xFFFF

print("-------------------------------------------------------------------------")
print("Response Header: ")
print("   ID: "+ hex(responseHeader.id))
print("   QR: %d" % (responseHeader.qr))
print("   Opcode: %d" % (responseHeader.opcode))
print("   AA: %d" % (responseHeader.aa))
print("   TC: %d" % (responseHeader.tc))
print("   RD: %d" % (responseHeader.rd))
print("   RA: %d" % (responseHeader.ra))
print("   Z: %d" % (responseHeader.z))
print("   RCODE: %d" % (responseHeader.rcode))
print("   QDCOUNT: %d" % (responseHeader.qdcount))
print("   ANCOUNT: %d" % (responseHeader.ancount))
print("   NSCOUNT: %d" % (responseHeader.nscount))
print("   ARCOUNT: %d" % (responseHeader.arcount))
print("")
print("Response Question: ")
print("   QNAME: " + responseQuestion.qname)
print("   QTYPE: %d" % (responseQuestion.qtype))
print("   QCLASS: %d" % (responseQuestion.qclass))
print("")
print("Response Answer: ")
print("   TYPE: %d" % (responseAnswer.type))
print("   CLASS: %d" % (responseAnswer.aclass))
print("   TTL: %d" % (responseAnswer.ttl))
print("   RDLENGTH: %d" % (responseAnswer.rdlength))
print("   RDATA: %d.%d.%d.%d        ## resolved IP address ##" % (responseAnswer.rdata[0], responseAnswer.rdata[1], responseAnswer.rdata[2], responseAnswer.rdata[3]))
