from tinyec import registry
import secrets  # crypto-secure random numbers generator


class EllipticCurveDiffieHellman:
    def __init__(self):
        self.curve = registry.get_curve("secp256r1")  # chosen curve
        self.private_key = self.__set_private_key()  # user's private key
        self.public_key = self.__set_public_key(self.private_key)  # user's public key

    # compress points for a more compact representation
    def __compress_point(self, point):
        return hex(point.x) + hex(point.y % 2)[2:]

    # generate the private key
    def __set_private_key(self):
        private_key = secrets.randbelow(self.curve.field.n)
        return private_key

    # set public key as point on the elliptic curve
    def __set_public_key(self, private_key):
        public_key = private_key * self.curve.g
        return public_key

    # encrypt the plaintext
    def encrypt_key(self):
        # generate the random key
        ciphertext_private_key = secrets.randbelow(self.curve.field.n)
        # represent the random key as elliptic curve coordinates
        ciphertext_public_key = ciphertext_private_key * self.curve.g
        # compute the shared key (key to send)
        shared_key = ciphertext_private_key * self.public_key
        return shared_key, ciphertext_public_key

    # decrypt the ciphertext
    def decrypt_key(self, cipher_text_public_key):
        # compute the shared key (key to send)
        shared_key = cipher_text_public_key * self.private_key
        return shared_key

    # represent the results of encryption and decryption processes
    def show_encryption_decryption_process(self):
        shared_encryption, public_key = self.encrypt_key()
        shared_decryption = self.decrypt_key(public_key)
        print('Public key of the user:', self.__compress_point(self.public_key))
        print('Private key of the user:', hex(self.private_key))
        print('Public key for the cipher-text:', self.__compress_point(public_key))
        print('Shared key for encryption:', self.__compress_point(shared_encryption))
        print('Shared key for decryption):', self.__compress_point(shared_decryption))
