from pwn import *

def attach_dbg(io,brk_pts=[],syms={},init_cmd=''):
    context.log_level='debug'
    context.terminal=['tmux','splitw','-h']
    
    elf_base=io.libs()[io.cwd+io.argv[0].strip('.')]

    cmd = ['b *'+hex(each+elf_base) for each in brk_pts] \
        + ['set $'+sym+'='+str(syms[sym]+elf_base) for sym in syms]

    cmd='\n'.join(cmd)+'\n'
    cmd += init_cmd
    print(cmd)
    gdb.attach(io,cmd)



def testing():
    io=process("./babyheap")
    p_attach_dbg(io,[0x102,0x200,0x2000])
    io.interactive()


if __name__=='__main__':
    testing()