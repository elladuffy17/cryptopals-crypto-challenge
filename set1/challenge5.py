# Implement repeating-key XOR

# Here is the opening stanza of an important work of the English language:

#    Burning 'em, if you ain't quick and nimble
#    I go crazy when I hear a cymbal

# Encrypt it, under the key "ICE", using repeating-key XOR.

# In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

# It should come out to:

#    0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
#    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

# Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

# Note the output is in hex

import binascii

#xor function
def repeating_xor(input, key_list):
    encryption = []
    print(input)
    for b in range(len(input)):    
        encryption.append(input[b] ^ key_list[b % len(key_list)])
    
    return(bytes(encryption))


input = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
#b_input = bytes(input, 'utf-8')

key = "ICE"
key_list = [ord(x) for x in key] #might want to make this more general with future iterations

final = repeating_xor(input, key_list)
#f_hex = binascii.hexlify(final) -- this worked but we had b' ... ' . Returns the hexadecimal representation of the binary data
f_hex = final.hex() #using this function we get the correct hex string format
print(f_hex)




