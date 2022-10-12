from ciphers.symmetric_ciphers.classical_ciphers.implementation.control import *
from implementation.implementation.caesar_cipher_permutation import *
from implementation.implementation.vigenere_cipher import *
from implementation.implementation.playfair_cipher import *
from implementation.implementation.bifid_cipher import *

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
