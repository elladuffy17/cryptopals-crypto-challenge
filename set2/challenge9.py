# Implement PKCS#7 padding

#A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. 
# But we almost never want to transform a single block; we encrypt irregularly-sized messages.

# One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. 
# The most popular padding scheme is called PKCS#7.

# So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

# "YELLOW SUBMARINE"
# ... padded to 20 bytes would be:

# "YELLOW SUBMARINE\x04\x04\x04\x04"

block = b'YELLOW SUBMARINE'
block_length = len(block)
required = 20

# important -- each byte added as padding is set to the number of bytes that are added
for i in range(block_length, required):
    value = bytes([required-block_length])
    block += value

print(block)

