from math import sqrt

from tinyec import registry
import secrets  # crypto-secure random numbers generator


from implementation.ec_operations import EllipticCurveOperations
from implementation.string_transformer import *


class EllipticCurveElGamal:
    def __init__(self):
        self.string_transformer = StringTransformer()  # StringTransformer() initialization
        self.ecc = EllipticCurveOperations()  # EllipticCurveOperations() initialization
        self.text = self.__get_input_data()  # text actions to be performed on
        self.curve = registry.get_curve("secp192r1")  # chosen elliptic curve
        self.private_key = self.__set_private_key()  # user's private key
        self.public_key = self.__set_public_key()  # user's public key

    # get the key, iv and the text to be encrypted or decrypted
    def __get_input_data(self):
        print('Input the plain-text')
        plain_text = input()
        return plain_text

    # generate the private key
    def __set_private_key(self):
        private_key = secrets.randbelow(self.curve.field.n)
        return private_key

    # compute the public key as point on the curve
    def __set_public_key(self):
        public_key = self.ecc.apply_double_addition_algorithm \
            (self.curve.g.x, self.curve.g.y, bin(self.private_key), self.curve.a, self.curve.field.p)
        return public_key

    # encrypt the plaintext
    def encrypt(self):
        # transform text into integer
        text_to_encrypt = self.string_transformer.convert_text_to_int(self.text)
        # represent text as point
        text_as_point = self.ecc.apply_double_addition_algorithm \
            (self.curve.g.x, self.curve.g.y, bin(text_to_encrypt), self.curve.a, self.curve.field.p)
        # generate key
        random_key = secrets.randbelow(self.curve.field.n)
        # compute shared key
        shared_key = self.ecc.apply_double_addition_algorithm \
            (self.curve.g.x, self.curve.g.y, bin(random_key), self.curve.a, self.curve.field.p)
        # compute the ciphertext
        ciphertext_public = self.ecc.apply_double_addition_algorithm \
            (self.public_key[0], self.public_key[1], bin(random_key), self.curve.a, self.curve.field.p)
        ciphertext_public = self.ecc.add_points \
            (ciphertext_public[0], ciphertext_public[1], text_as_point[0], text_as_point[1],
             self.curve.a, self.curve.field.p)
        return ciphertext_public, shared_key, random_key, text_as_point

    def decrypt(self, ciphertext_public, shared_key):
        # get the point to subtract
        x, y = self.ecc.apply_double_addition_algorithm \
            (shared_key[0], shared_key[1], bin(self.private_key), self.curve.a, self.curve.field.p)
        # subtract from the ciphertext to decrypt the point representation of the plaintext
        decrypted_text_as_point = self.ecc.add_points \
            (ciphertext_public[0], ciphertext_public[1], x, -y, self.curve.a, self.curve.field.p)
        # perform Baby step Giant step to find the numeric value of the point representation of the plaintext
        # order = int(sqrt(self.curve.field.n)) + 1
        # for i in range(1, order):
        #     point_message = self.ecc.apply_double_addition_algorithm(self.curve.g.x, self.curve.g.y, bin(i),
        #                                                              self.curve.a, self.curve.field.p)
        #     for j in range(1, order):
        #         check = self.ecc.apply_double_addition_algorithm(self.curve.g.x, self.curve.g.y, bin(j * order),
        #                                                          self.curve.a, self.curve.field.p)
        #         check = self.ecc.add_points(self.public_key[0], self.public_key[1], check[0], -check[1],
        #                                     self.curve.a, self.curve.field.p)
        #         if check == point_message:
        #             decrypted_text = (i + j * order) % self.curve.field.p
        #             return decrypted_text
        return decrypted_text_as_point

    # represent the results of encryption and decryption processes
    def show_encryption_decryption_process(self):
        ciphertext_public, shared_key, random_key, plaintext_point = self.encrypt()
        decrypted_text_point = self.decrypt(ciphertext_public, shared_key)
        print(f'Plaintext point on curve: {plaintext_point}')
        print(f'Generate private_key: {self.private_key}')
        print(f'Computed public key: {self.private_key}')
        print(f'Generated random key: {random_key}')
        print(f'Computed shared key: {shared_key}')
        print(f'Ciphertext point on curve: {ciphertext_public}')
        print(f'Decrypted message point on curve: {decrypted_text_point}')
