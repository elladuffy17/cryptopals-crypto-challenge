# An ECB/CBC detection oracle

# Now that you have ECB and CBC working:

# Write a function to generate a random AES key; that's just 16 random bytes.

# Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

# The function should look like:

#       encryption_oracle(your-input)
#       => [MEANINGLESS JIBBER JABBER]

# Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

# Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

# Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from binascii import b2a_base64, a2b_base64 # returns with a newline - just way it was implemented
from base64 import b64decode, b64encode
from random import randint

# Need XOR function... because CBC takes plaintext block and it gets XOR-ed with the ciphertext of the preceding block.
def xor_ella(first, second):
    return bytes(a ^ b for a, b in zip(first, second))

def key_AES():
    key_16bytes = get_random_bytes(16)
    return key_16bytes

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

def encrypt_cbc(plaintext, key, IV):
	#break up the plaintext into 16 bytes
	plaintext_block = [plaintext[i:i+AES.block_size] for i in range(0, len(plaintext), AES.block_size)]
	final_ciphertext = b''
	# for initial XOR function
	prev_cipher = IV

	for i in range(0, len(plaintext_block)):
		pad_block = pad_pkcs7(plaintext_block[i], AES.block_size)
		i_xor = xor_ella(pad_block, prev_cipher) #add initial plaintext block to IV
		i_encrypt = encrypt_ecb(i_xor, key)
		final_ciphertext += i_encrypt
		
		#set the cipher to be used in next round
		prev_cipher = i_encrypt
	
	return final_ciphertext

def encryption_oracle(pt_input):
    aes_key = key_AES() # 16-bytes == 128-bit
    # append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.
    
    append_bytes1 = get_random_bytes(randint(5, 10))
    append_bytes2 = get_random_bytes(randint(5, 10))
    updated_plaintext = pad_pkcs7(append_bytes1 + pt_input + append_bytes2, AES.block_size)

    # pick a mode to use - no matter what, remember that AES uses a 128-bit block size
    mode = randint(1,2)
    if mode == 1: #ECB mode
        mode_use = 'ECB'
        final = encrypt_ecb(updated_plaintext, aes_key)
  
    else: #CBC mode
        mode_use = 'CBC'
        # need a random IV for CBC, which should be the same size of the block - 128-bit/16 bytes
        IV = get_random_bytes(16)
        final = encrypt_cbc(updated_plaintext, aes_key, IV)
  
    print('mode:', mode_use)
    return final

def detect_mode(ciphertext_check, block_size):
    # This function should detect if the code was encrypted with either ECB or CBC
    # Well we know that for ECB mode it would be easy to decrypt whereas in CBC, it is difficult for the attacker to decrypt the ciphertext.
    # ECB is stateless and determinstic, the same 16 byte plaintext block will always produce the same 16 byte ciphertext
    # Therefore, we might see patterns. Since we know this is a weakness of ECB, let's see if there are patterns within the ciphertext
    # If not it is fair to assume that CBC mode was used
    examine_bytes = [ciphertext_check[i : i+block_size] for i in range(0, len(ciphertext_check), block_size)] # Build list of 16-byte blocks
    unique_bytes = set(examine_bytes) # removes duplicates and returns a set object containing only the unique elements.

    if len(unique_bytes)/len(examine_bytes) < 1:
        return 'ECB' #patterns found
    else:
        return 'CBC'

def main():
    #plain_text = b'a' * (AES.block_size * 5)
    plain_text = b'Arbitrary data to encrypt ' * 50
    result = encryption_oracle(plain_text)
    mode = detect_mode(result, AES.block_size)
    print('The mode used to encrypt was:', mode)

if __name__ == '__main__':
	main()