# class that contains selecting methods
class Control:
    # select the cipher to be used
    def get_cipher(self):
        print('Choose the number that corresponds to th cipher you want use:\n'
              '1 - Grain Cipher (stream cipher)\n'
              '2 - DES Cipher(block cipher)\n')
        cipher = int(input())
        if cipher not in range(1, 3):
            raise Exception('You should choose an integer between 1 and 2')
        return cipher

    # select the action to be performed
    def get_action(self):
        print('Choose the action you want to perform;\n'
              '1 - Encrypt\n'
              '2 - Decrypt')
        action = int(input())
        if action not in range(1, 3):
            raise Exception('You should choose an integer between 1 and 2')
        return action
