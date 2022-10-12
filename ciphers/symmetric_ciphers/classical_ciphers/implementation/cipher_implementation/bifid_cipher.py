class BifidCipher:
    def __init__(self):
        self.keyword, self.key, self.word = self.__get_input_data()
        self.normal_alphabet = [chr(i) for i in range(65, 91)]  # english alphabet in the correct order
        self.alphabet = []  # permuted alphabet
        self.matrix = [[0 for i in range(5)] for j in range(5)]  # a 5 by 5 matrix
        self.dictionary = {}  # a dictionary for letter position in the matrix

    # get the keyword, key and the text to be encrypted or decrypted
    def __get_input_data(self):
        print('Input the keyword. It must contain only latin letters and blank '
              'spaces:')
        keyword = input()
        # check the rightfulness of the keyword input
        if not all(x.isalpha() or x.isspace() for x in keyword):
            raise Exception('Keyword should contain only latin letters and blank spaces')
        print('Input the key for block sizes. It should be an integer:')
        # check the rightfulness of the key input
        try:
            key = int(input())
        except:
            raise Exception('Block sizes key should be an integer')
        print('Input the text you want to be encrypted or decrypted:')
        word = input()
        # check the rightfulness of the word input
        if not all(x.isalpha() or x.isspace() for x in word):
            raise Exception('The text should contain only latin letters and blank spaces')
        return keyword, key, word

    # make uppercase all letters in the input word and remove spaces
    def __set_word(self, word):
        word = word.upper()
        word = word.replace(' ', '')
        word = word.replace('J', 'I')
        return word

    # append the keyword to the permuted alphabet
    def __set_keyword(self):
        self.keyword = self.__set_word(self.keyword)
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

    # put the letters from the input text in blocks of key size and merge row and column indexes of the same blocks
    def __get_encoding_blocks(self):
        blocks = [self.word[i:i + self.key] for i in range(0, len(self.word), self.key)]
        rows = [[] for i in range(len(blocks))]
        columns = [[] for i in range(len(blocks))]
        encoded_blocks = [[] for i in range(len(blocks))]
        i = 0
        while i < len(blocks):
            block = blocks[i]
            for letter in block:
                # add row index
                rows[i].append(self.dictionary[letter][0])
                # add column index
                columns[i].append(self.dictionary[letter][1])
            # merge row and column indexes of the same group
            encoded_blocks[i] = rows[i] + columns[i]
            i += 1
        return encoded_blocks

    #  put the letters from the input text in blocks of key size and separate row and column indexes
    def __get_decoding_blocks(self):
        blocks = [self.word[i:i + self.key] for i in range(0, len(self.word), self.key)]
        rows = [[] for i in range(len(blocks))]
        columns = [[] for i in range(len(blocks))]
        decoding_blocks = [[] for i in range(len(blocks))]
        i = 0
        while i < len(blocks):
            block = blocks[i]
            for letter in block:
                # add row and column indexes to the block
                decoding_blocks[i] += self.dictionary[letter]
            split = len(decoding_blocks[i]) // 2
            # get row indexes of the decrypted text
            rows[i] = decoding_blocks[i][:split]
            # get column indexes of the decrypted text
            columns[i] = decoding_blocks[i][split:]
            i += 1
        return rows, columns

    # encrypt the text
    def encode_text(self):
        self.__build_matrix()
        self.word = self.__set_word(self.word)
        encoded_blocks = self.__get_encoding_blocks()
        encoded_text = ''
        for block in encoded_blocks:
            # get the letter with row and column indexes by 2 integers in order of their appearance
            i = 0
            while i < len(block):
                row = block[i]
                column = block[i + 1]
                encoded_text += self.matrix[row][column]
                i += 2
        return encoded_text

    # decrypt the text
    def decode_text(self):
        self.__build_matrix()
        self.word = self.__set_word(self.word)
        rows, columns = self.__get_decoding_blocks()
        decoded_text = ''
        # get the letter with row and column indexes as integers for each individual corresponding group
        for i in range(len(rows)):
            for j in range(len(rows[i])):
                row = rows[i][j]
                column = columns[i][j]
                decoded_text += self.matrix[row][column]
        return decoded_text
