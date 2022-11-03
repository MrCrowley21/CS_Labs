from string_transformer import *
from implementation.control import *
from implementation.cipher_implementation.grain_cipher import *
from implementation.cipher_implementation.des_cipher import *

transformer = StringTransformer()

# initiate control class
control = Control()
# choose the cipher to be use
cipher_nr = control.get_cipher()
if cipher_nr == 1:
    cipher = GrainCipher()
else:
    cipher = DESCipher()

#  choose the action to be performed
action = control.get_action()
if action == 1:
    print(cipher.encrypt_text())
else:
    print(cipher.decrypt_text())
