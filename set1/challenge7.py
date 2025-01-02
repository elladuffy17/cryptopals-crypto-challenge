# AES in ECB mode

# The Base64-encoded content in the file 7.txt has been encrypted via AES-128 in ECB mode under the key

# "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

# Decrypt it. You know the key, after all.

# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

# Do this with code.
# You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB.

# In ECB mode, the plaintext is broken into blocks of a given size (128 bits in this case), and the encryption algorithm is run on each block of plaintext individually.
# Article to help understand the process: https://wgallagher86.medium.com/aes-encryption-826f3a4403e7
# AES is a block cipher encryption method, meaning that the plaintext is split into blocks of a specified size, and the encryption method is applied to each block.
# 128 bit key — 10 rounds of encryption

# The Process
# Key Expansion — each round of encryption needs it’s own key, so based on our key size we’re going to need 10 leys. To do this, we’ll go through a process called key expansion on our initial given key.
# The encryption rounds (10 rounds based on a 128 bit key size)
#   a. Substitute Bytes: Based on a lookup table we will switch bytes
#   b. Shift Rows: Bytes are organized onto a table, and bytes are shifted a number of columns based on what row they are in
#   c. Mix Columns: Columns in the created table are multiplied against a constant table(not done in the last round).
#   d. Add Round Key: XOR against the key for the round.

# It is important to understand how this works, but in practice you should use a standard library
# Cryptohack site has practice so you can learn internals of the cipher

import base64
# Problem with pycrypto .. it is unmaintained and has had issues such as buffer overflow, etc.
# Instead, use a fork of it known as pycryptodome
from Crypto.Cipher import AES

def decrypt_AES_128_ECBmode(text, key):
	return AES.new(key, AES.MODE_ECB).decrypt(text)

f = open('7.txt', 'r') # this file has been base64d -- What does that mean? People encode the binary data into characters. Base64 is one of these types of encodings.

# lines = f.readlines() -- reads a single line of the file, allowing the user to parse a single line without necessarily reading the entire file
lines = f.read() # reads the file as an individual string, and so allows relatively easy file-wide manipulations

key = b'YELLOW SUBMARINE' #8 bits per char, therefore it is a 128 bit key or 16 byte

ciphertext = base64.b64decode(lines) # Used to decode data that has been encoded using the Base64 scheme
plaintext = decrypt_AES_128_ECBmode(ciphertext, key)
print(plaintext)
  