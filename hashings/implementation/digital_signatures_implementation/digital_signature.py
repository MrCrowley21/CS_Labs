from hashlib import sha256

from implementation.digital_signatures_implementation.rsa_cipher import *


class DigitalSignature:
    def __init__(self):
        self.rsa = RSACipher()  # initialize the RSA cipher cass
        self.documents_keys = {}  # keep the document and the document its corresponded public key

    # hash the given data
    def __hash_data(self, data):
        hashing = sha256(data.encode('utf-8')).hexdigest()
        return hashing

    # sign the input string
    def digital_sign_document(self, document):
        # hash the document
        hashed_document = self.__hash_data(document)
        # get the hash of the encrypted data and the public key of the user
        encrypted_hashing, public_key = self.rsa.encrypt(hashed_document)
        # add the public key to the dictionary
        self.documents_keys[document] = [encrypted_hashing, public_key]
        return document, encrypted_hashing, public_key

    # verify the signature
    def verify_digital_signature(self, document):
        # hash the document
        hashed_document = self.__hash_data(document)
        try:
            # decrypt the received ciphertext
            decrypted_hashing = self.rsa.decrypt(self.documents_keys[document][0], self.documents_keys[document][1])
            # compare the hashes
            if hashed_document == decrypted_hashing:
                return f'Success! The signature is valid!'
            else:
                return f'Not a valid signature'
        except KeyError:
            print('Not such document was signed')


