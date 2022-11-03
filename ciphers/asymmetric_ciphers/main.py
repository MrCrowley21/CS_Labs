from implementation.cipher_implementation.ecdh_cipher import *
from implementation.cipher_implementation.ec_el_gamal import *
from implementation.ec_operations import *
from implementation.control import *

# initiate control class
control = Control()
# choose the cipher to be use
cipher_nr = control.get_cipher()
if cipher_nr == 1:
    cipher = EllipticCurveDiffieHellman()
else:
    cipher = EllipticCurveElGamal()

# output the result
cipher.show_encryption_decryption_process()
