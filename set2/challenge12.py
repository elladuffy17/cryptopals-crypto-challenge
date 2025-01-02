# Byte-at-a-time ECB decryption (Simple)

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from binascii import b2a_base64, a2b_base64 # returns with a newline - just way it was implemented
from base64 import b64decode, b64encode
from random import randint

# Create a consistent but unknown key (for instance, assign a single random key, once, to a global variable).
global_key = get_random_bytes(AES.block_size)

def pad_pkcs7(input_block, required):
    block_length = len(input_block)
    pad_required = required - (block_length % required)
    
    # important -- each byte added as padding is set to the number of bytes that are added
    input_block += bytes([pad_required]) * pad_required
    return input_block

def encrypt_ecb(text, key):
	cipher = AES.new(key, AES.MODE_ECB)
	aesCiphertext = cipher.encrypt(text)
	return aesCiphertext

def encryption_oracle(pt_input):
    string = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    string_64 = b64decode(string)
    updated_plaintext = pad_pkcs7(pt_input + string_64, AES.block_size)

    # always using ECB mode
    final = encrypt_ecb(updated_plaintext, global_key)

    return final

def detect_ecb(ciphertext_check, block_size):
    # ECB is stateless and determinstic, the same 16 byte plaintext block will always produce the same 16 byte ciphertext
    # Therefore, we might see patterns. Since we know this is a weakness of ECB, let's see if there are patterns within the ciphertext
    examine_bytes = [ciphertext_check[i : i+block_size] for i in range(0, len(ciphertext_check), block_size)] # Build list of 16-byte blocks
    unique_bytes = set(examine_bytes) # removes duplicates and returns a set object containing only the unique elements.

    if len(unique_bytes)/len(examine_bytes) < 1:
        return True #patterns found
    else:
        return False
     

def main():
    #find block size
    my_byte = b''
    initial_length = len(encryption_oracle(my_byte)) #padded would be added to ensure the input can be broken up into block size chunks
    while True:
        my_byte += b'E'
        temp_len = len(encryption_oracle(my_byte))
        if temp_len != initial_length:
            break
    
    #detect the function is using ECB
    block_size = temp_len - initial_length
    print(detect_ecb(encryption_oracle(b'E'*block_size*5), block_size))
    number_of_blocks = int(temp_len/block_size)

    #craft an input one byte shorter than the block size
    start_input = b'E' * (block_size-1)
    unknown_string = b''
    
    for number in range(number_of_blocks):
        for i in range(block_size):
            unknown_string_b = b''
            i_input = b'E' * (block_size-1-i)
            i_result = encryption_oracle(i_input)[number*block_size:block_size*(number+1)]
            temp = [start_input + bytes([b]) for b in range(256)]
            for strings in temp:
                result = encryption_oracle(strings)[:block_size]
                if result == i_result:
                    decrypt_byte = strings[-1:]
                    unknown_string_b+=decrypt_byte
                    start_input = start_input[1:] + decrypt_byte
                    break
            unknown_string += unknown_string_b

    end_result = unknown_string.decode()
    print(end_result)

if __name__ == '__main__':
     main()
