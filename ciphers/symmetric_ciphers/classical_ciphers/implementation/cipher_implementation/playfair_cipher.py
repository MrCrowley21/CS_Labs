class PlayfairCipher:
    def __init__(self, keyword, word):
        # this line is for non-server version
        # self.keyword, self.word = self.__get_input_data()
        self.keyword = keyword
        self.word = word
        self.processed_word = []  # list of groups by 2 obtained from the input text
        self.normal_alphabet = [chr(i) for i in range(65, 91)]  # english alphabet in the correct order
        self.alphabet = []  # permuted alphabet
        self.matrix = [[0 for i in range(5)] for j in range(5)]  # a 5 by 5 matrix
        self.dictionary = {}  # a dictionary for letter position in the matrix

    # get the keyword and the text to be encrypted or decrypted
    # this function is for non-server version
    # def __get_input_data(self):
    #     print('Input the keyword. It must contain only latin letters and blank '
    #           'spaces:')
    #     keyword = input()
    #     # check the rightfulness of the keyword input
    #     if not all(x.isalpha() or x.isspace() for x in keyword):
    #         raise Exception('Keyword should contain only latin letters and blank spaces')
    #     print('Input the text you want to be encrypted or decrypted:')
    #     word = input()
    #     # check the rightfulness of the word input
    #     if not all(x.isalpha() or x.isspace() for x in word):
    #         raise Exception('The text should contain only latin letters and blank spaces')
    #     return keyword, word

    # split the input text in the groups by 2 according to the rules
    def __separate_plain_text(self):
        # make all letters uppercase, remove blank spaces and replace letter 'J'
        self.word = self.word.upper()
        self.word = self.word.replace(' ', '')
        self.word = self.word.replace('J', 'I')
        # group the letters by 2 according to the rules
        i = 0
        while i < len(self.word):
            letter_1 = self.word[i]
            # ensure the added letter is not the analyzed one
            if letter_1 != 'X':
                filler_letter = 'X'
            else:
                filler_letter = 'Z'
            # add fill letter if the last letter cannot be grouped and make the group
            if i + 1 == len(self.word):
                self.word += filler_letter
                letter_2 = self.word[-1]
                i += 2
            # add fill letter in case group with the same letters and make the group
            elif letter_1 == self.word[i + 1]:
                letter_2 = filler_letter
                i += 1
            # make the group in normal conditions
            else:
                letter_2 = self.word[i + 1]
                i += 2
            self.processed_word.append([letter_1, letter_2])

    # append the keyword to the permuted alphabet
    def __set_keyword(self):
        # make all letters uppercase, remove blank spaces and replace letter 'J'
        self.keyword = self.keyword.upper()
        self.keyword = self.keyword.replace(' ', '')
        self.keyword = self.keyword.replace('J', 'I')
        # add keyword at the beginning of the alphabet
        for letter in self.keyword:
            if letter not in self.alphabet:
                self.alphabet.append(letter)

    # complete the permuted alphabet with the remained letters
    def __get_permuted_alphabet(self):
        for letter in self.normal_alphabet:
            if letter not in self.alphabet and letter != 'J':
                self.alphabet.append(letter)

    # arrange permuted alphabet in th 5 by 5 matrix
    def __build_matrix(self):
        self.__set_keyword()
        self.__get_permuted_alphabet()
        k = 0
        for i in range(5):
            for j in range(5):
                # add value to the matrix
                self.matrix[i][j] = self.alphabet[k]
                # complete dictionary with the position of the letter
                self.dictionary[self.alphabet[k]] = [i, j]
                k += 1

    # group the letters in the encoded text by 2
    def __group_plain_text(self):
        # make all letters uppercase, remove blank spaces and replace letter 'J'
        self.word = self.word.upper()
        self.word = self.word.replace(' ', '')
        self.word = self.word.replace('J', 'I')
        # restore the groups of 2
        i = 0
        # check if valid encryption with the used cipher
        if len(self.word) % 2:
            raise Exception('Not valid encrypted text with Playfair Algorithm')
        while i < len(self.word):
            letter_1 = self.word[i]
            letter_2 = self.word[i + 1]
            i += 2
            self.processed_word.append([letter_1, letter_2])

    # encrypt the text
    def encrypt_text(self):
        encoded_text = ''
        self.__separate_plain_text()
        self.__build_matrix()
        # encode each letter from the input text, according to the block it is in
        for block in self.processed_word:
            letter_1, letter_2 = block
            row_1, column_1 = self.dictionary[letter_1]
            row_2, column_2 = self.dictionary[letter_2]
            # in case the same row
            if row_1 == row_2:
                encoded_text += self.matrix[row_1][(column_1 + 1) % 5] + self.matrix[row_2][(column_2 + 1) % 5]
            # in case the same column
            elif column_1 == column_2:
                encoded_text += self.matrix[(row_1 + 1) % 5][column_1] + self.matrix[(row_2 + 1) % 5][column_2]
            # in case different row and column
            else:
                encoded_text += self.matrix[row_1][column_2] + self.matrix[row_2][column_1]
        return encoded_text

    # decrypt the text
    def decrypt_text(self):
        decoded_text = ''
        self.__group_plain_text()
        self.__build_matrix()
        # decode each block from the input text, according to the block it is in
        for block in self.processed_word:
            letter_1, letter_2 = block
            row_1, column_1 = self.dictionary[letter_1]
            row_2, column_2 = self.dictionary[letter_2]
            # in case the same row
            if row_1 == row_2:
                decoded_text += self.matrix[row_1][(column_1 - 1) % 5] + self.matrix[row_2][(column_2 - 1) % 5]
            # in case the same column
            elif column_1 == column_2:
                decoded_text += self.matrix[(row_1 - 1) % 5][column_1] + self.matrix[(row_2 - 1) % 5][column_2]
            # in case different row and column
            else:
                decoded_text += self.matrix[row_1][column_2] + self.matrix[row_2][column_1]
        return decoded_text

