# class that contains selecting methods
class Control:
    # select the cipher to be used
    def get_cipher(self):
        print('Choose the number that corresponds to the cipher you want use:\n'
              '1 - Elliptic-curve Diffie–Hellman Cipher (ECDH)\n'
              '2 - Elliptic Curve ElGamal Cipher\n')
        cipher = int(input())
        if cipher not in range(1, 3):
            raise Exception('You should choose an integer between 1 and 2')
        return cipher
