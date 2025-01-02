# Fixed XOR

# Write a function that takes two equal-length buffers and produces their XOR combination.

# Example:
# If your function works properly, then when you feed it the string:

# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:

# 686974207468652062756c6c277320657965
# ... should produce:

# 746865206b696420646f6e277420706c6179

# About XOR....
# Any expression following the AB’ + A’B form 
# (two AND gates and an OR gate) may be replaced by a 
# single Exclusive-OR gate.

import binascii

def xor_ella(first, second):
    return bytes(a ^ b for a, b in zip(first, second))
    # note: Python's zip() function creates an iterator that will aggregate elements from two or more iterables.

# 1c0111001f010100061a024b53535009181c
buffer_1 = str(input("Enter your first string: "))
bytes1 = binascii.unhexlify(buffer_1)

# 686974207468652062756c6c277320657965
buffer_2 = str(input("Enter your second string: "))
bytes2 = binascii.unhexlify(buffer_2)

if len(bytes1) == len(bytes2):
    # Perform XOR operation
    xor = xor_ella(bytes1, bytes2)
    hex_xor = binascii.hexlify(xor)

print(hex_xor)

