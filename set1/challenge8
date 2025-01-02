#Detect AES in ECB mode

#In the file 8.txt are a bunch of hex-encoded ciphertexts.

#One of them has been encrypted with ECB.

#Detect it.

#Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.#

import binascii

def check_ecb(bytes1):
    examine_bytes = [bytes1[i : i+16] for i in range(0, len(bytes1), 16)] # Build list of 16-byte blocks

    for block in examine_bytes:
        if examine_bytes.count(block) > 1:
            print("Found it!")
            return True

    return False
    

f = open('8.txt', 'r') # this file has a bunch of hex-encoded ciphertexts - I am assuming there is aciphertext per line
lines = f.readlines()
file_list = []

for i in range(len(lines)):
    try:
        remove_n = lines[i].strip()
        bytes1 = binascii.unhexlify(remove_n.encode('utf8')) #use unhexilfy which converts from hex encoded string to binary data
        #bytes1 = base64.b64encode(bytes.fromhex(remove_n)).decode() -- since we are investigateing bytes, and base 64 charcaters are 6 bits, we don't use this
        file_list.append(bytes1)
    except UnicodeDecodeError:
        pass

print(len(file_list[1])) #the length of each element in the list is 160 ... therefore 160 bytes, which gives us 10 different blocks

# How do we detect ECB.... our hint is that since it is stateless and determinstic, the same 16 byte plaintext block will always produce the same 16 byte ciphertext
# Therefore, we might see patterns. Since we know this is a weakness of ECB, let's see if any of these ciphertexts have patterns
# In a random sequence of bytes, the likelihood of two 16-byte blocks matching is 1/2^128 or very small! So, if two blocks match then our sequence is very unlikely to be random.

for i in range(len(file_list)):
    bool = check_ecb(file_list[i])
    if bool == True:
        print(file_list[i])