class CaesarCipherPermutation:
    def __init__(self):
        self.keyword, self.shift_key, self.word = self.__get_input_data()
        self.normal_alphabet = [chr(i) for i in range(65, 91)]  # english alphabet in the correct order
        self.alphabet = [] # permuted alphabet

    # get the keyword, key and the text to be encrypted or decrypted
    def __get_input_data(self):
        print('Input the keyword that will be used for permutation. It must contain only latin letters and blank '
              'spaces:')
        keyword = input()
        # check the rightfulness of the keyword input
        if not all(x.isalpha() or x.isspace() for x in keyword):
            raise Exception('Keyword should contain only latin letters and blank spaces')
        print('Input the key for sifting. It should be an integer:')
        # check the rightfulness of the key input
        try:
            key = int(input())
        except:
            raise Exception('The shifting key should be an integer')
        print('Input the text you want to be encrypted or decrypted:')
        word = input()
        # check the rightfulness of the key input
        if not all(x.isalpha() or x.isspace() for x in word):
            raise Exception('The text should contain only latin letters and blank spaces')
        return keyword, key, word

    # initiate the alphabet with permutation
    def __set_keyword_permutation(self):
        # make all letters uppercase and remove blank spaces
        self.keyword = self.keyword.upper()
        self.keyword = self.keyword.replace(' ', '')
        # put the word in the beginning of the alphabet with permutation
        for letter in self.keyword:
            if letter not in self.alphabet:
                self.alphabet.append(letter)

    # complete the alphabet with permutation with the remaining letters
    def __get_permuted_alphabet(self):
        for letter in self.normal_alphabet:
            if letter not in self.alphabet:
                self.alphabet.append(letter)

    # get permuted alphabet and normalize text input
    def __prepare_components(self):
        # get permuted alphabet
        self.__set_keyword_permutation()
        self.__get_permuted_alphabet()
        # make all letters in the text uppercase and remove the blank spaces
        self.word = self.word.upper()
        self.word = self.word.replace(' ', '')

    # encrypt the text
    def encode_text(self):
        self.__prepare_components()
        encoded_word = ''
        for i in self.word:
            # use formula for encryption
            encoded_word += self.alphabet[(self.normal_alphabet.index(i) + self.shift_key) % 26]
        return encoded_word

    # decrypt the text
    def decode_text(self):
        self.__prepare_components()
        decoded_word = ''
        for i in self.word:
            # use formula for decryption
            decoded_word += self.normal_alphabet[(self.alphabet.index(i) - self.shift_key) % 26]
        return decoded_word
