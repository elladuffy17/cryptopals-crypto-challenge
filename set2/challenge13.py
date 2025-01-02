#ECB cut-and-paste

#Write a k=v parsing routine, as if for a structured cookie. The routine should take:

#foo=bar&baz=qux&zap=zazzle
#... and produce:

#{
#  foo: 'bar',
#  baz: 'qux',
#  zap: 'zazzle'
#}
#(you know, the object; I don't care if you convert it to JSON).

#Now write a function that encodes a user profile in that format, given an email address. You should have something like:

#profile_for("foo@bar.com")
#... and it should produce:

#{
#  email: 'foo@bar.com',
#  uid: 10,
#  role: 'user'
#}
#... encoded as:

#email=foo@bar.com&uid=10&role=user

#Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, 
# but don't let people set their email address to "foo@bar.com&role=admin".

#Now, two more easy functions. Generate a random AES key, then:

#   A) Encrypt the encoded user profile under the key; "provide" that to the "attacker".
#   B) Decrypt the encoded user profile and parse it.

#Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.

import re
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import math

def generate_aes_key():
    key_16bytes = get_random_bytes(16)
    return key_16bytes

#ECB mode encryption/decryption functions from previous challenges
def encrypt_ecb(text, key):
	cipher = AES.new(key, AES.MODE_ECB)
	aesCiphertext = cipher.encrypt(text)
	return aesCiphertext

def decrypt_ecb(text, key):
	cipher = AES.new(key, AES.MODE_ECB)
	aesPlaintext = cipher.decrypt(text)
	return unpad(aesPlaintext, AES.block_size)

def parsing_routine(input):
    resulting_object = {}
    new = input.split('&')
    for object in new:
        pair = object.split('=')
        resulting_object[pair[0]] = pair[1]
    return resulting_object

def profile_for(input_email):
    #input_check = input_email.split('&')
    #check for username, '@', and a domain
    #for obj in input_check:
    #    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    #    if re.match(pattern, obj):
    #        email = obj
    #        break

    email_remove = input_email.replace('&', '')
    email = email_remove.replace('=', '')
    #pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    #if re.match(pattern, email) is None:
    #    print("Error... not an email %s", email)
    
    email_str = 'email=' + email 
    #hard coded values
    uid_str = 'uid=' + '10'
    role_str = 'role=' + 'user'
    encoded_string = email_str+'&'+uid_str+'&'+role_str

    #print(parsing_routine(encoded_string))
    return encoded_string #TShis function should be returning the encoded string instead of the profile object

def main():
    aesKey = generate_aes_key()
    user_profile = profile_for("foo@bar.com") #confirms that this function ignores role=admin

    profile_bytes = pad(user_profile.encode('utf-8'), AES.block_size)
    encryptedProfile = encrypt_ecb(profile_bytes, aesKey)
    decryptedProfile = decrypt_ecb(encryptedProfile,aesKey).decode('utf-8')
    parse_result = parsing_routine(decryptedProfile) #returns our profile object
    print(parse_result)

    #now we want to figure out how to actually get role=admin profile...
    #print(decryptedProfile) #result: email=foo@bar.com&uid=10&role=user
    og_len = len(decryptedProfile) #result: length is 34
    role_index = decryptedProfile.find('role') #result: the index is 25
    
    new_profile = 'email=foo@bar.com&uid=10&role=admin'
    new_length = len(new_profile) #result: length is 35
    new_role = 'role=admin'
    new_r_length = len(new_role) #result: length is 10

    #Due to the length of the ciphertext/plaintext... there are 2 full blocks and then a third which gets padded
    first_block = decryptedProfile[0:16] #result: email=foo@bar.co 
    second_block = decryptedProfile[16:32] #result: m&uid=10&role=us
    third_block = decryptedProfile[32:34] #result: er

    #for our goal new profile...
    first_block_new = new_profile[0:16] #result: email=foo@bar.co 
    second_block_new = new_profile[16:32] #result: m&uid=10&role=ad
    third_block_new = new_profile[32:35] #result: min

    #But... we can only use the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, to make a role=admin profile."
    #Choose an email that pushes 'user' and/or 'admin' to its own block... Therefore block 1 and 2 will be the same between the two cases
    
    num_blocks = math.ceil(float((len("&uid=10") + len("email=") + len("&role="))/AES.block_size)) #round up since here we don't account for the actual email
    in_email = "e"*(num_blocks*AES.block_size - len("&uid=10") - len("email=") - len("&role=") - len("@bar.com")) + "@bar.com"
    #Craft a special email so that the string admin and its PKCS#7 padding will be in its own block
    admin_pad = pad('admin'.encode('utf-8'), AES.block_size) # admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b 
    admin_email = "e"*(AES.block_size - len("email=")) +  admin_pad.decode()
    
    adminProfile = profile_for(admin_email)
    enc_adminProfile = encrypt_ecb(pad(adminProfile.encode('utf-8'), AES.block_size), aesKey)

    userProfile = profile_for(in_email)
    enc_userProfile = encrypt_ecb(pad(userProfile.encode('utf-8'), AES.block_size), aesKey)

    admin_final = enc_userProfile[:num_blocks*AES.block_size] + enc_adminProfile[AES.block_size:AES.block_size*2] #replace encrypted version of role=user with an encrypted role=admin 
    decrypt_final = decrypt_ecb(admin_final, aesKey).decode('utf-8')
    parse_final = parsing_routine(decrypt_final)
    print(parse_final)


if __name__ == '__main__':
     main()
