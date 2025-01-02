# Implement CBC mode

# CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms 
# individual blocks.

# In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

# The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

# Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to
#  test), and using your XOR function from the previous exercise to combine them.

# The file 10.txt is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

# Don't cheat.
# Do not use OpenSSL's CBC code to do CBC mode, even to verify your results. What's the point of even doing this stuff if you aren't going to learn from it?

import base64
from binascii import unhexlify, b2a_base64, a2b_base64, hexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Need XOR function... because CBC takes plaintext block and it gets XOR-ed with the ciphertext of the preceding block.
def xor_ella(first, second):
    return bytes(a ^ b for a, b in zip(first, second))

def pad_pkcs7(input_block, required):
    block_length = len(input_block)
    pad_required = required - (block_length % required)
    
    # important -- each byte added as padding is set to the number of bytes that are added
    input_block += bytes([pad_required]) * pad_required
    return input_block

# Need this function when doing the decryption, which we use to check our CBC mode
def unpad_pkcs7(input_block):
	# We want to remove the pkcs7 padding from the block

    padding = input_block[input_block[-1]::-1] # start at end of block and reverse the slice which makes it work to beginning of block
    if not all(padding[byte] == len(padding) for byte in range(0, len(padding))): # 'if not' checks if the all() func returns False
        return input_block
    return input_block[:input_block[-1]:-1]


# From challenge7
def decrypt_ecb(text, key):
	cipher = AES.new(key, AES.MODE_ECB)
	aesPlaintext = cipher.decrypt(text)
	return unpad_pkcs7(aesPlaintext)

# Instead, we want to encrypt instead of decrypt
def encrypt_ecb(text, key):
	cipher = AES.new(key, AES.MODE_ECB)
	aesCiphertext = cipher.encrypt(text)
	return aesCiphertext

def encrypt_cbc(plaintext, key, IV):
	#break up the plaintext into 16 bytes
	plaintext_block = [plaintext[i: i+AES.block_size] for i in range(0, len(plaintext), AES.block_size)]
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

def decrypt_cbc(ciphertext, key, IV):
	ciphertext_block = [ciphertext[i: i+AES.block_size] for i in range(0, len(ciphertext), AES.block_size)]
	final_plaintext = b''
	prev_block = IV

	for i in range(0, len(ciphertext_block)):
		i_decrypt = decrypt_ecb(ciphertext_block[i], key)
		i_xor = xor_ella(i_decrypt, prev_block)
		final_plaintext += i_xor

		prev_block = ciphertext_block[i]
	
	return unpad_pkcs7(final_plaintext)

def main():
	key = b'YELLOW SUBMARINE'
	# The IV is ASCII 0: \x00. We need 16 of these zero-bytes because the IV must be exactly 128-bits (16 bytes) long, which is the AES block size.
	IV = b'\x00' * AES.block_size # OUr fake 0th ciphertext block

	ciphertext = b''.join([a2b_base64(line.strip()) for line in open("10.txt").readlines()])

	plaintext = decrypt_cbc(ciphertext, key, IV)
	cbc_ciphertext = encrypt_cbc(plaintext, key, IV)
	
	for line in str(plaintext, 'utf-8').split("\n"):
		print(line)

	# Ensure we get right result
	result = b2a_base64(cbc_ciphertext).strip().decode()
	with open('10_result.txt', 'w') as outfile:
		if len(result) > 60:
			outfile.write('\n'.join(result[i:i+60] for i in range(0,len(result), 60)))
		else:
			outfile.write(result)

	# Conduct test with my custom message
	#message = b'hello my name is ella duffy!!'
	#message_cipher = encrypt_cbc(message, key, IV)
	#message_plain = decrypt_cbc(message_cipher, key, IV)
	#print(message_plain.decode('utf-8'))

if __name__ == '__main__':
	main()