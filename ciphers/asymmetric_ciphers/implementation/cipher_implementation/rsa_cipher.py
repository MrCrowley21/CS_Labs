from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP


# digital_sign_implementation using RSA library provided by Python
class RSACipher:
    def __init__(self):
        self.length = 1024  # define the key length
        self.public_key, self.private_key = self.__generate_keys()  # generate the keys

    # generate the pair of keys
    def __generate_keys(self):
        private_key = RSA.generate(self.length)
        public_key = private_key.public_key()
        return public_key, private_key

    # encrypt the plaintext
    def encrypt(self, plaintext):
        # initiate the encryptor
        encryptor = PKCS1_OAEP.new(self.private_key)
        # encrypt the input text
        ciphertext = encryptor.encrypt(bytes(plaintext, encoding='utf-8'))
        return ciphertext, self.public_key

    # decrypt the ciphertext
    def decrypt(self, ciphertext, public_key):
        try:
            # initiate the encryptor
            encryptor = PKCS1_OAEP.new(public_key)
            # decrypt the input text if possible
            plaintext = encryptor.decrypt(ciphertext).decode('utf-8')
            return plaintext
        except:
            return 'Non-valid digital signature'
