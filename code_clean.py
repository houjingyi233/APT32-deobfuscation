#!/usr/bin/python

import re
import struct
import collections
from capstone import *
from keystone import *

#we need to store all location of data and patch them to
#0x90(nop) to prevent wrong decompile result in capstone
switch_data = {}
switch_data[0x2906B65] = 10
switch_data[0x291C5FC] = 21
switch_data[0x29363D0] = 6
switch_data[0x29364A8] = 6
switch_data[0x29623E8] = 3
switch_data[0x2962464] = 8
switch_data[0x29624D0] = 4
switch_data[0x2962574] = 3
switch_data[0x2962600] = 8
switch_data[0x296266C] = 4
switch_data[0x2962758] = 3
switch_data[0x29627D4] = 8
switch_data[0x2962840] = 4
switch_data[0x29628E4] = 3
switch_data[0x2962970] = 8
switch_data[0x29629DC] = 4
switch_data[0x29651B9] = 32
switch_data[0x2968F58] = 8
switch_data[0x2969CB2] = 8
switch_data[0x29727ED] = 12

#offset between new data_start and old data_start
offset = 0

jmp_attr = {}
class jmpattr():
    junk = -2           #jmp +5
    dead = -1           #dead jmp
    uninitialized = 0   #not a jmp or "jmp edx" etc
    normal = 1          #normal jmp
    # > 1:jmp loop

mark_jmp = {}
#jmp in a dead jmp 
jmp_circle = []
#pos of junk popfd
pos_popfd = []
#pos of junk pushfd
pos_pushfd = []
#mark repeat code when we restore control flow
repeat = {}
#store code are going to be read from input
read_code = {}
#junk pushfd/popfd,key is address,value is whether it's junk code or not(1 or 0)
junk_code = {}
#junk pushfd/popfd,key is address of pushfd,value is address of popfd
junk_code_pair = {}
#store code are going to be write to output
write_code = {}
#store pairs about addr in read and addr in write to fix offset
code_mapping = {}
#all kind of conditional jmp
str_j = {"ja","jnc","jae","jne","jb","jng","jbe","jnge","jc","jnl",
"jcxz","jnle","je","jno","jecxz","jnp","jg","jns","jge","jnz",
"jl","jo","jle","jp","jpe","jna","jpo","jnae","js","jnb","jz","jnbe"} 
#keystone
ks = Ks(KS_ARCH_X86, KS_MODE_32)
#structure to present an assembly code  

class disasms:
    def __init__(self, size, last, address, codebytes, op_str, mnemonic):
        self.size = size
        self.last = last
        self.address = address
        self.bytes = codebytes 
        self.op_str = op_str
        self.mnemonic = mnemonic

#you should change these values according to your sample
code_start = 0x2901000
data_start = 0x297BA1C
end_address = 0x29E3FFF
write_addr = code_start

def init_code(address, last, size, codebytes, op_str, mnemonic):
    #patching all jmp to register to call
    repeat[address] = -1
    mark_jmp[address] = -1
    junk_code[address] = 0
    code_mapping[address] = []
    jmp_attr[address] = jmpattr.uninitialized
    read_code[address] = disasms(size, last, address, codebytes, op_str, mnemonic)
    if size == 2 and mnemonic == "jmp" and op_str in {"eax", "ebx", "ecx", "edx", "edi", "esi"}:
        read_code[address].mnemonic = "call"
        read_code[address].bytes[1] -= 0x10

def init():

    for i in switch_data:
        offset = 0
        cnt = switch_data[i] * 4
        while cnt != 0:
            code[i - code_start + offset] = 0x90
            cnt -= 1
            offset += 1

    last = 0
    for i in md.disasm(code, code_start):
        if last == 0: 
            last = i.address
            init_code(i.address, 0, i.size, bytearray(i.bytes), i.op_str, i.mnemonic)
        else:
            init_code(i.address, last, i.size, bytearray(i.bytes), i.op_str, i.mnemonic)
            last = i.address
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

#expand junk code area,sometimes there are still many junk code before pushf/after popf 
def expand_pushfd_popfd(address, flag):
    while True:
        
        if (read_code[address].mnemonic in {"push", "pop"} 
        and read_code[address].op_str in {"eax","ebx","ecx","edx"}):
            junk_code[address] = 1
            if flag == 1: address = read_code[address].last
            else: address += read_code[address].size
            continue
        
        if (read_code[address].mnemonic in 
            {"bswap","cwd","cbw","cdq","lahf","cdq","aas",
            "stc","shl","neg","dec","inc","cmc","inc","not",
            "ror","bt","aad","div","sar","xchg","clc","daa"}):
            junk_code[address] = 1
            if flag == 1: address = read_code[address].last
            else: address += read_code[address].size
            continue
        
        if read_code[address].mnemonic in {"mov","lea"}:
            matchobj = re.search(r'esp|ebp', read_code[address].op_str)
            if matchobj:
                #code like "mov	dword ptr [esp], 0x293bf4d" is not junk code
                matchobj = re.search(r'^dword\sptr\s\[esp\],\s0x(?P<address>(\w*))$', read_code[address].op_str) 
                if matchobj:
                    push_address = matchobj.groupdict()['address']
                    push_address = int(push_address, 16)
                    if push_address > code_start and push_address < data_start:
                        break
                junk_code[address] = 1
                if flag == 1: address = read_code[address].last
                else: address += read_code[address].size
                continue
            matchobj = re.search(r'\sax,|\sbx,|\scx,|\sdx,', read_code[address].op_str)
            if matchobj:
                junk_code[address] = 1
                if flag == 1: address = read_code[address].last
                else: address += read_code[address].size
                continue
        
        break

#process obfuscate code about pushfd/popfd 
def process_pushfd_popfd():

    global read_code
    global pos_popfd
    global pos_pushfd

    #we have to consider pairs like (pushfd popfd) (pushfd pushfd popfd) (pushfd popfd popfd) (pushfd pushfd popfd popfd)
    for i in md.disasm(code, code_start):
    
        if i.address >= data_start:
            break
            
        if i.mnemonic == "pushfd":
            if len(pos_popfd) != 0:
                addr = pos_popfd.pop()
                for j in pos_pushfd:
                    if addr - j < 0x500:
                        junk_code_pair[j] = addr
                        while j <= addr: 
                            junk_code[j] = 1
                            j += read_code[j].size
                        break
                pos_popfd = []
                pos_pushfd = []            
            pos_pushfd.append(i.address)
            continue
    
        if i.mnemonic == "popfd":
            pos_popfd.append(i.address)
            if len(pos_pushfd) == len(pos_popfd):
                if i.address - pos_pushfd[0] < 0x500:
                    junk_code_pair[pos_pushfd[0]] = i.address
                    while pos_pushfd[0] <= i.address:
                        junk_code[pos_pushfd[0]] = 1
                        pos_pushfd[0] += read_code[pos_pushfd[0]].size
                pos_popfd = []
                pos_pushfd = []
            continue

    #expand junk code area,sometimes there are still many junk code before pushf/after popf 
    for i in junk_code_pair:
        
        end = junk_code_pair[i] + read_code[junk_code_pair[i]].size
        start = read_code[i].last

        expand_pushfd_popfd(end, 0)
        expand_pushfd_popfd(start, 1)
    
    #sometimes,there is a conditional jmp before pushf and a reverse conditional jmp 
    #after popf,so we need to patch the conditional jmp before pushf to jmp and expand 
    #junk code area:from right after jmp to reverse conditional jmp after popf
    for i in junk_code_pair:
        cnt1 = 5
        addr1 = i
        while cnt1 >= 0:
            cnt1 -= 1
            addr1 = read_code[addr1].last            
            if read_code[addr1].mnemonic in str_j: break
            if read_code[addr1].mnemonic == "call": cnt1 = -1 
        if cnt1 >= 0:
            cnt2 = 10
            addr2 = junk_code_pair[i]
            while cnt2 >= 0:
                cnt2 -= 1                
                addr2 += read_code[addr2].size
                if read_code[addr2].mnemonic in str_j: break
                if read_code[addr2].mnemonic == "call": cnt2 = -1 
            if cnt2 >= 0:
                if read_code[addr1].op_str == read_code[addr2].op_str:
                    read_code[addr1].mnemonic = "jmp"
                    read_code[addr1].size = 5 
                    read_code[addr1].bytes[0] = 0xE9
                    fix_offset(addr1, int(read_code[addr1].op_str, 16), read_code)
                    read_code[addr1].bytes = read_code[addr1].bytes[:-1]
                    
                    #create a nop as placeholder
                    init_code(addr1 + 5, addr1, 1, bytearray([0x90]), "", "nop") 
                    read_code[addr1 + 6].last = addr1 + 5
                    
                    start = i
                    while start >= addr1 + read_code[addr1].size:
                        junk_code[start] = 1
                        start = read_code[start].last
                    
                    #patching conditional jmp after popf to nop 
                    #to prevent it disturb finding repeat code
                    if read_code[addr2].size == 2:
                        
                        init_code(addr2, read_code[addr2].last, 1, bytearray([0x90]), "", "nop") 
                        init_code(addr2 + 1, addr2, 1, bytearray([0x90]), "", "nop") 
                        read_code[addr2 + 2].last = addr2 + 1

                        end = junk_code_pair[i]
                        while end < addr2 + 2:
                            junk_code[end] = 1
                            end += read_code[end].size
                    
                    else:
                        
                        init_code(addr2, read_code[addr2].last, 1, bytearray([0x90]), "", "nop") 
                        init_code(addr2 + 1, addr2, 1, bytearray([0x90]), "", "nop") 
                        init_code(addr2 + 2, addr2 + 1, 1, bytearray([0x90]), "", "nop") 
                        init_code(addr2 + 3, addr2 + 2, 1, bytearray([0x90]), "", "nop") 
                        init_code(addr2 + 4, addr2 + 3, 1, bytearray([0x90]), "", "nop") 
                        init_code(addr2 + 5, addr2 + 4, 1, bytearray([0x90]), "", "nop") 
                        read_code[addr2 + 6].last = addr2 + 5

                        end = junk_code_pair[i]
                        while end < addr2 + 6:
                            junk_code[end] = 1
                            end += read_code[end].size

    #sometimes,there is a "push 0xAAAAAAAA" or "mov dword ptr [esp], 0xAAAAAAAA" 
    #before pushf and a retn after popf,we patch them to call 0xAAAAAAAA 
    new_call = {}
    fix_flag = {}

    for i in junk_code_pair:
        
        cnt1 = 5
        addr1 = i
        while cnt1 >= 0:
            
            cnt1 -= 1
            addr1 = read_code[addr1].last            
            
            if read_code[addr1].mnemonic == "push":
                matchobj = re.search(r'^0x(?P<address>(\w*))$', read_code[addr1].op_str) 
                if matchobj:
                    new_op_str = matchobj.groupdict()['address']
                    push_address = int(new_op_str, 16)
                    if push_address > code_start and push_address < data_start:
                        new_call[addr1] = 1
                        fix_flag[addr1] = 0
                        junk_code[addr1] = 0
                        read_code[addr1].mnemonic = "call"
                        read_code[addr1].bytes[0] = 0xE8
                        fix_offset(addr1, push_address, read_code)
                        addr1 += read_code[addr1].size
                        while addr1 < i:
                            junk_code[addr1] = 1
                            addr1 += read_code[addr1].size
                        break

            if read_code[addr1].mnemonic == "mov":
                matchobj = re.search(r'^dword\sptr\s\[esp\],\s0x(?P<address>(\w*))$', read_code[addr1].op_str) 
                if matchobj:
                    new_op_str = matchobj.groupdict()['address']
                    push_address = int(new_op_str, 16)
                    if push_address > code_start and push_address < data_start:
                        new_call[addr1] = 1
                        fix_flag[addr1] = 0
                        junk_code[addr1] = 0
                        read_code[addr1].size = 5
                        read_code[addr1].mnemonic = "call"
                        read_code[addr1].op_str = hex(push_address)
                        read_code[addr1].bytes[0] = 0xE8
                        fix_offset(addr1, push_address, read_code)
                        read_code[addr1].bytes = read_code[addr1].bytes[:-2]
                        init_code(addr1 + 5, addr1, 1, bytearray([0x90]), "", "nop") 
                        init_code(addr1 + 6, addr1 + 5, 1, bytearray([0x90]), "", "nop") 
                        read_code[addr1 + 7].last = addr1 + 6
                        addr1 += read_code[addr1].size
                        while addr1 < i:
                            junk_code[addr1] = 1
                            addr1 += read_code[addr1].size
                        break
        
        if cnt1 >= 0:
            cnt2 = 10
            addr2 = junk_code_pair[i]
            while cnt2 >= 0:
                cnt2 -= 1                
                addr2 += read_code[addr2].size
                if addr2 in junk_code_pair: break
                if read_code[addr2].mnemonic in {"ret","jmp"}: break
                if read_code[addr2].mnemonic == "call": cnt2 = -1  
            if cnt2 >= 0:
                end = junk_code_pair[i]
                while end < addr2:
                    junk_code[end] = 1
                    end += read_code[end].size
    
    read_code = collections.OrderedDict(sorted(read_code.items()))

    caller = []  
    callee = []

    for i in new_call:
        if fix_flag[i] == 1: continue
        caller = []  
        callee = [] 
        caller.append(i)
        callee.append(int(read_code[i].op_str, 16))
        addr = i + read_code[i].size
        while True:
            while junk_code[addr] == 1: addr += read_code[addr].size
            if addr in new_call: 
                caller.append(addr) 
                callee.append(int(read_code[addr].op_str, 16))
                addr = addr + read_code[addr].size
                continue
            else:
                break
        
        if len(caller) > 1:
            for i in caller:
                addr = callee.pop()
                fix_offset(i, addr, read_code)
                read_code[i].op_str = hex(addr) 
                fix_flag[i] = 1    

#if code here is jmp,consider both 0xE9 with four bytes offset and 0xE8 with 1 byte 
#offset,cannot just judge whether pos.mnemonic == "jmp", because there switch jmp code    
def is_jmp(pos,codes):
    try:
        if (codes[pos].mnemonic == "jmp"                      
      and ((codes[pos].size == 5 and codes[pos].bytes[0] == 0xE9)    
        or (codes[pos].size == 2 and codes[pos].bytes[0] == 0xEB))):
            return 1
        else:
            return 0
    #this only happens when we meet weird code in process_write_code
    except KeyError:
        return 0  

def decide_jmp_attr(address):
    
    global jmp_attr
    global jmp_circle
    
    jmp_circle.append(address)
    addr = int(read_code[address].op_str, 16)
    
    while True:
            
        if is_jmp(addr, read_code):
            if addr in jmp_circle:
                if len(jmp_circle) == 1:                        
                    return jmpattr.dead
                else: 
                    for i in jmp_circle:
                        if jmp_attr[i] == jmpattr.uninitialized: jmp_attr[i] = len(jmp_circle)
                    return len(jmp_circle) 
            else: 
                return decide_jmp_attr(addr)

        #switch jmp or retn
        if read_code[addr].mnemonic in {"ret", "jmp"}:
            return jmpattr.normal

        addr += read_code[addr].size

def store_jmp_attr():
    for i in read_code:    
        if is_jmp(i, read_code) and i < data_start:
            
            global jmp_circle
            jmp_circle.clear()
            
            if i + 5 == int(read_code[i].op_str, 16):
                jmp_attr[i] = jmpattr.junk       
            else:
                jmp_attr[i] = decide_jmp_attr(i)

def do_the_mark(address):
    start = address

    while True:

        if mark_jmp[address] == 1:
            break

        if (read_code[address].mnemonic == "ret"
        or (read_code[address].mnemonic == "jmp" and jmp_attr[address] != jmpattr.junk)):
            while True:
                repeat[address] = 1
                if address == start: break
                address = read_code[address].last
            break

        address += read_code[address].size

def mark_repeat_code():

    for i in jmp_attr:

        if jmp_attr[i] == jmpattr.normal or jmp_attr[i] > 1:

            if jmp_attr[i] > 1: mark_jmp[i] = 1
            address = int(read_code[i].op_str, 16)
            tmpaddr = address

            if tmpaddr > code_start: 
            
                tmpaddr = read_code[tmpaddr].last

                if (read_code[tmpaddr].mnemonic == "ret"
                or read_code[tmpaddr].mnemonic == "int3"
               or (read_code[tmpaddr].mnemonic == "nop" and junk_code[tmpaddr] == 1)
               or (jmp_attr[tmpaddr] != jmpattr.junk and read_code[tmpaddr].mnemonic == "jmp")):
                    
                    do_the_mark(address)

            if tmpaddr == code_start:

                do_the_mark(address)
    
#return address after skip junk code,if return value equals to 0 means wrong 
def skip_junk_code(addr):
    try:
        while True:
            cases = 0

            if read_code[addr].mnemonic == "int3":
                cases = 1 
            if is_jmp(addr, read_code) and jmp_attr[addr] == jmpattr.junk:
                cases = 2
            if junk_code[addr] == 1:
                cases = 3
            
            if cases == 0: return addr
            elif cases == 1: addr += 1
            elif cases == 2: addr += 5
            elif cases == 3: addr += read_code[addr].size
    #this only happens when we meet weird code in process_write_code
    except KeyError:
        return 0

#deal with unconditional jmp
def deal_jmp(jmpto_address,cnt):

    global write_addr
        
    while True:
        
        jmpto_address = skip_junk_code(jmpto_address)
        
        if is_jmp(jmpto_address, read_code):
            if cnt > 0:
                cnt -= 1
                if cnt > 1:
                    deal_jmp(int(read_code[jmpto_address].op_str, 16), cnt)
                    break
                else:
                    write_code[write_addr] = disasms(
                    read_code[jmpto_address].size, 
                    read_code[jmpto_address].last, 
                    read_code[jmpto_address].address,
                    bytearray(read_code[jmpto_address].bytes), 
                    read_code[jmpto_address].op_str, 
                    read_code[jmpto_address].mnemonic) 
                        
                    code_mapping[jmpto_address].append(write_addr)
                    write_addr += 5
                    jmpto_address += read_code[jmpto_address].size
                    break 
            else:
                deal_jmp(int(read_code[jmpto_address].op_str, 16), cnt)
                break

        write_code[write_addr] = disasms(
        read_code[jmpto_address].size,
        read_code[jmpto_address].last,  
        read_code[jmpto_address].address,
        bytearray(read_code[jmpto_address].bytes), 
        read_code[jmpto_address].op_str, 
        read_code[jmpto_address].mnemonic)

        if read_code[jmpto_address].mnemonic in {"ret","jmp"}:

            code_mapping[jmpto_address].append(write_addr)
            write_addr += read_code[jmpto_address].size
            jmpto_address += read_code[jmpto_address].size
            break

        code_mapping[jmpto_address].append(write_addr)
        #patching all 2 bytes conditional/unconditional jmp to 6/5 bytes
        if ( read_code[jmpto_address].mnemonic in str_j 
         and read_code[jmpto_address].size == 2 
         and read_code[jmpto_address].address < data_start):
            write_addr += 6 
        elif (is_jmp(jmpto_address, read_code) and jmp_attr[jmpto_address] == jmpattr.dead 
         and read_code[jmpto_address].size == 2 
         and read_code[jmpto_address].address < data_start):
            write_addr += 5
        else:
            write_addr += read_code[jmpto_address].size
        jmpto_address += read_code[jmpto_address].size

#now we skip junk code and restore control flow
def process_read_code():

    global read_code
    global write_addr

    for i in read_code:
        
        if repeat[i] == 1:
            continue
        
        elif junk_code[i] == 1:
            continue

        elif (read_code[i].mnemonic == "int3" 
        and i < data_start):
            continue

        elif (is_jmp(i, read_code) 
        and jmp_attr[i] == jmpattr.junk 
        and i < data_start):
            continue

        elif (is_jmp(i, read_code) 
        and (jmp_attr[i] == jmpattr.normal or jmp_attr[i] > 1)
        and i < data_start):
            
            jmpto_address = int(read_code[i].op_str, 16)      

            if jmp_attr[i] == jmpattr.normal:
                deal_jmp(jmpto_address, 0)
            else:
                deal_jmp(jmpto_address, jmp_attr[i])
                                
        else:

            write_code[write_addr] = disasms(
            read_code[i].size,
            read_code[i].last, 
            read_code[i].address,
            bytearray(read_code[i].bytes), 
            read_code[i].op_str, 
            read_code[i].mnemonic)
            
            code_mapping[i].append(write_addr)
            #patching all 2 bytes conditional/unconditional jmp to 6/5 bytes
            if read_code[i].mnemonic in str_j and read_code[i].size == 2 and read_code[i].address < data_start:
                write_addr += 6
            elif (is_jmp(i, read_code) 
            and jmp_attr[i] == jmpattr.dead 
            and read_code[i].size == 2 
            and i < data_start):
                write_addr += 5
            else: 
                write_addr += read_code[i].size

#using keystone to generate asm code
def gen_asm(code, i):
    x = bytearray()
    encoding, count = ks.asm(code)
    #keystone seems to have some bug cannot generate asm 
    #code sometimes.let's have a second try to make sure. 
    if encoding == None:
        encoding, count = ks.asm(code)
    for j in encoding:
        x += struct.pack('B', j)
    write_code[i].bytes = x

#fix offset in unconditional jmp and jmp/call/push/mov 0xAAAAAAAA
def fix_offset(addr, pos, codes):

    if codes[addr].mnemonic in {"push", "mov"}:
        x = pos
    else:    
        if codes[addr].size == 2 and codes[addr].mnemonic != "jmp":
            x = pos - addr - 6
        elif codes[addr].size == 2 and codes[addr].mnemonic == "jmp":
            x = pos - addr - 5
        else:
            x = pos - addr - codes[addr].size
    
    if x < 0:
        x = x + 0x100000000

    new_str = hex(x)
    while len(new_str) < 10:
        new_str = "0x" + "0" + new_str[2:]

    y = codes[addr].bytes
    if codes[addr].size == 2:
        if codes[addr].mnemonic == "jmp":
            y[0] = 0xE9
            y[1] = int(new_str[-2:],16)
            y.append(int(new_str[-4:-2],16))
            y.append(int(new_str[-6:-4],16))
            y.append(int(new_str[-8:-6],16))
        else:
            if codes[addr].mnemonic == "jo":
                y[0] = 0x0F
                y[1] = 0x80
            if codes[addr].mnemonic == "jno":
                y[0] = 0x0F
                y[1] = 0x81
            if codes[addr].mnemonic in {"jb", "jc", "jnae"}:
                y[0] = 0x0F
                y[1] = 0x82
            if codes[addr].mnemonic in {"jnb", "jnc", "jae"}:
                y[0] = 0x0F
                y[1] = 0x83
            if codes[addr].mnemonic in {"jz", "je"}:
                y[0] = 0x0F
                y[1] = 0x84
            if codes[addr].mnemonic in {"jnz", "jne"}:
                y[0] = 0x0F
                y[1] = 0x85
            if codes[addr].mnemonic in {"jbe", "jna"}:
                y[0] = 0x0F
                y[1] = 0x86
            if codes[addr].mnemonic in {"jnbe", "ja"}:
                y[0] = 0x0F
                y[1] = 0x87
            if codes[addr].mnemonic == "js":
                y[0] = 0x0F
                y[1] = 0x88
            if codes[addr].mnemonic == "jns":
                y[0] = 0x0F
                y[1] = 0x89
            if codes[addr].mnemonic in {"jp", "jpe"}:
                y[0] = 0x0F
                y[1] = 0x8A
            if codes[addr].mnemonic in {"jnp", "jpo"}:
                y[0] = 0x0F
                y[1] = 0x8B
            if codes[addr].mnemonic in {"jl", "jnge"}:
                y[0] = 0x0F
                y[1] = 0x8C
            if codes[addr].mnemonic in {"jnl", "jge"}:
                y[0] = 0x0F
                y[1] = 0x8D
            if codes[addr].mnemonic in {"jle", "jng"}:
                y[0] = 0x0F
                y[1] = 0x8E
            if codes[addr].mnemonic in {"jnle", "jg"}:
                y[0] = 0x0F
                y[1] = 0x8F
            y.append(int(new_str[-2:],16))
            y.append(int(new_str[-4:-2],16))
            y.append(int(new_str[-6:-4],16))
            y.append(int(new_str[-8:-6],16))
    elif codes[addr].size == 5:
        y[1] = int(new_str[-2:],16)
        y[2] = int(new_str[-4:-2],16)
        y[3] = int(new_str[-6:-4],16)
        y[4] = int(new_str[-8:-6],16)
    elif codes[addr].size == 6:
        y[2] = int(new_str[-2:],16)
        y[3] = int(new_str[-4:-2],16)
        y[4] = int(new_str[-6:-4],16)
        y[5] = int(new_str[-8:-6],16)
    codes[addr].bytes = y

#return correspond address of output file in input file,if return value equals 
#to 0 means sth wrong.we need to return the nearest address to keep code same
def lookup_code_mapping(addr, i):
    try:
        if not code_mapping[addr]: return 0
        smallest = 0x100000000
        for k in code_mapping[addr]:
            if abs(k - i) < smallest: 
                smallest = abs(k - i)
                nearest_addr = k
        if smallest != 0x100000000: return nearest_addr
        else: return 0
    #this only happens when we meet weird code in 
    #process_write_code and fix offset in data 
    except KeyError:
        return 0
    
#get addr in out file corresponding to addr in input file
def get_address_code(addr, i):
    write_address = 0
    if addr >= code_start and addr < data_start:
        while is_jmp(addr, read_code): addr = int(read_code[addr].op_str, 16)
        write_address = skip_junk_code(addr)
        write_address = lookup_code_mapping(write_address, i)
    elif addr >= data_start and addr < end_address:
        write_address = addr + offset
    return write_address
   
#fix offset in write code
def process_write_code():
    
    for i in write_code:

        if i < data_start + offset:
        
            #fix unconditional jmp
            #fix call/push 0xAAAAAAAA
            #fix jmp 0xAAAAAAAA
            if (write_code[i].mnemonic in str_j
           or ((write_code[i].mnemonic == "call" or write_code[i].mnemonic == "push") and write_code[i].size == 5)
           or (is_jmp(i, write_code))):
                address = int(write_code[i].op_str, 16)
                write_address = get_address_code(address, i)
                if write_address != 0:

                    print ("---fix-offset---")
                    print (hex(i))
                    print (hex(write_address))
                    
                    fix_offset(i, write_address, write_code)           

            #examples:
            #1.mov dword ptr [ecx], 0xAAAAAAAA
            #2.mov dword ptr [ebp - 0x10], 0xAAAAAAAA
            #3.cmp dword ptr [0xAAAAAAAA], 0xBBBBBBBB(0xAAAAAAAA will be fixed later)
            #4.mov/cmp eax/ecx/edx/ebx/esp/ebp/esi/edi, 0xAAAAAAAA
            #if we use keystone to generate machine code,the code should not depend on it's address.
            #it seems we cannot specify address of code in ks.asm(code),keystone just think address
            #of code is zero.It's perfect to use keystone here,size of ins have too much situations.
            matchobj = re.search(r',\s0x(?P<address>(\w*))$', write_code[i].op_str)
            if matchobj:
                address = matchobj.groupdict()['address']
                address = int(address, 16)
                write_address = get_address_code(address, i)
                if write_address != 0:
                    write_code[i].op_str = re.sub(r'0x(\w*)$', hex(write_address), write_code[i].op_str)
                    new_op_str = write_code[i].mnemonic + " " + write_code[i].op_str       
                    
                    print ("----gen-asms----")
                    print (hex(i))
                    print (new_op_str)

                    gen_asm(new_op_str, i)

            #examples:
            #1.cmp dword ptr [0xAAAAAAAA], 0xBBBBBBBB(0xBBBBBBBB should be fixed before)
            #2.mov eax, dword ptr [0xAAAAAAAA]
            #3.mov dword ptr [0xAAAAAAAA], eax
            #4.jmp dword ptr [edi*4 + 0xAAAAAAAA]
            #5.call/jmp/push dword ptr [0xAAAAAAAA]
            #6.fmul	qword ptr [0x297cec8]
            matchobj = re.search(r'word\sptr\s\[(((\S+)\*(\S+)\s\+\s)*)0x(?P<address>(\S*))((\s\+\s(\S+)\*(\S+))*)\]', write_code[i].op_str)
            if matchobj: 
                address = matchobj.groupdict()['address']
                address = int(address, 16)
                write_address = get_address_code(address, i)
                if write_address != 0:
                    write_code[i].op_str = re.sub(r'0x(\w*)\]', hex(write_address) + "]", write_code[i].op_str)
                    new_op_str = write_code[i].mnemonic + " " + write_code[i].op_str

                    print ("----gen-asms----")
                    print (hex(i))
                    print (new_op_str)

                    gen_asm(new_op_str, i)

                #handle some weird code like
                #seg000:029628D5 jmp dword ptr ds:loc_29628DC+4[eax*4]
                #seg000:029628DC jmp ds:jpt_296290A[ecx*4]
                else:

                    print ("address:")
                    print (hex(i))
                    print (hex(address))

                    if address >= code_start and address < data_start:
                        j = 0
                        result = 0
                        while result == 0:
                            j += 1
                            address -= 1  
                            result = lookup_code_mapping(address, i)
                            if j>10: break
                        if result != 0:
                            write_address = result + j
                            write_code[i].op_str = re.sub(r'0x(\w*)\]', hex(write_address) + "]", write_code[i].op_str)
                            new_op_str = write_code[i].mnemonic + " " + write_code[i].op_str
                        
                            print ("----gen-asms----")
                            print (hex(i))
                            print (new_op_str)
        
                            gen_asm(new_op_str, i)
 
#now patch data in output file
def patch_data():
    
    f_read = open("2901000.bin","rb+")
    f_write = open("2901000-res.bin","rb+")

    #patch switch_data in code
    for i in switch_data:
        switch_write = lookup_code_mapping(i, 0)
        
        f_read.seek(0)
        f_write.seek(0)
        f_read.seek(i - code_start)
        f_write.seek(switch_write - code_start)

        while switch_data[i] != 0:
            addr, = struct.unpack('<I', f_read.read(0x4))
            write_address = get_address_code(addr, 0)
            if write_address != 0:
                print ("---fix-offset---")
                print (hex(write_address))
                f_write.write(struct.pack('<I', write_address))
            switch_data[i] -= 1

    #patch data after data_start
    f_read.seek(0)
    f_write.seek(0)
    f_read.seek(data_start - code_start)
    f_write.seek(code_mapping[data_start][0] - code_start)

    i = 0

    while True:

        addr, = struct.unpack('<I', f_read.read(0x4))
        write_address = get_address_code(addr, 0)
        if write_address != 0:
            print ("---fix-offset---")
            print (hex(write_address))
            f_write.write(struct.pack('<I', write_address))
        
        i += 1
        if i > end_address - data_start - 4: break
        
        f_read.seek(0)
        f_write.seek(0)
        f_read.seek(data_start - code_start + i)
        f_write.seek(code_mapping[data_start][0] - code_start + i)
    
    f_read.close()
    f_write.close()

if __name__ == '__main__': 

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True 

    f_read = open("2901000.bin","rb+")
    code = bytearray(f_read.read())
    f_read.close()
    
    init()

    process_pushfd_popfd()
    
    store_jmp_attr()

    mark_repeat_code()

    process_read_code()

    #print code_mapping
    for i in code_mapping:
        print ("---mapping---")
        print (hex(i))
        print ("-------")
        for j in code_mapping[i]:
            print (hex(j))

    #count offset between new data_start and old data_start
    offset = code_mapping[data_start][0] - data_start

    process_write_code()
    
    #write to file
    f_write = open("2901000-res.bin","wb+")
    for i in write_code:
        f_write.write(write_code[i].bytes)
    f_write.close()

    patch_data()