from Control import *
from Caesar_cipher_permutation import *
from Vigenere_cipher import *
from Playfair_cipher import *
from Bifid_cipher import *

# initiate control class
control = Control()
# choose the cipher to be use
cipher_nr = control.get_cipher()
if cipher_nr == 1:
    cipher = CaesarCipherPermutation()
elif cipher_nr == 2:
    cipher = VigenereCipher()
elif cipher_nr == 3:
    cipher = PlayfairCipher()
else:
    cipher = BifidCipher()
#  choose the action to be performed
action = control.get_action()
if action == 1:
    print(cipher.encode_text())
else:
    print(cipher.decode_text())
