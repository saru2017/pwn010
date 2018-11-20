import struct

def p(val):
    return struct.pack('<I', val)



def u(val):
    return struct.unpack('<I', val)[0]



def read_until(sock, s):
    line = b""
    while line.find(s) < 0:
        line += sock.recv(1)
        print("reading: ", end="")
        print(line)



def p64(val):
    return struct.pack('<Q', val)



def u64(val):
    return struct.unpack('<Q', val)[0]

