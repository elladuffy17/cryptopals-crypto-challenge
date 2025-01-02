# Byte-at-a-time ECB decryption (Harder)

# What makes Challenge 14 harder than Challenge 12 is detecting those random bytes we append as prefix....
# The hint is: you're using all the tools you already have; no crazy math is required. Think "STIMULUS" and "RESPONSE".

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from binascii import b2a_base64, a2b_base64 # returns with a newline - just way it was implemented
from base64 import b64decode, b64encode
from random import randint
from os.path import commonprefix

block_size = AES.block_size
global_key = get_random_bytes(AES.block_size)

# Generate a random count of random bytes to prepend to each plaintext -- must be larger than one block so we can detect where it ends ?

random_prefix = get_random_bytes(randint(1, block_size*5)) # Might need to adjust range

def pad_pkcs7(input_block, required):
    block_length = len(input_block)
    pad_required = required - (block_length % required)
    
    # Important -- each byte added as padding is set to the number of bytes that are added
    input_block += bytes([pad_required]) * pad_required
    return input_block

def encrypt_ecb(text, key):
	cipher = AES.new(key, AES.MODE_ECB)
	aesCiphertext = cipher.encrypt(text)
	return aesCiphertext

def encryption_oracle(pt_input):
    string = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    string_64 = b64decode(string)
    updated_plaintext = pad_pkcs7(random_prefix + pt_input + string_64, AES.block_size)

    # Always using ECB mode
    final = encrypt_ecb(updated_plaintext, global_key)

    return final

def main():
    # How do we find where those random bytes start and end...
    # What we have to leverage about ECB is that a piece of plaintext is ALWAYS encrypted to the same ciphertext
    # Therefore let's vary our input and compare the ciphertext
    block_size = AES.block_size
    number_of_blocks = int(len(encryption_oracle(b'E'*0))/block_size)
    rand_block = 0

    my_byte = b''
    initial_enc = encryption_oracle(my_byte)
    print(initial_enc)

    print("\n")

    my_byte1 = b'E'
    second_enc = encryption_oracle(my_byte1)
    print(second_enc)

    #now let's compare the two to see where the random prefix ends
    for i in range(number_of_blocks):
        if initial_enc[i*block_size:(i+1)*block_size] == second_enc[i*block_size:(i+1)*block_size]:
            rand_block += 1
        else:
             break
        
    #Check our logic
    if rand_block*block_size != len(commonprefix([initial_enc, second_enc])):
         print("Error!!")
    
    # The E was inserted somewhere in the next block - rand_block+1



if __name__ == '__main__':
     main()

     
