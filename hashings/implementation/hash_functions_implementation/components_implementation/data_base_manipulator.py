import sqlite3
from sqlite3 import Error
import pandas as pd
from implementation.hash_functions_implementation.components_implementation.password_hashing import *

password_hashing = PasswordHashing()


class DataBase:
    def __init__(self):
        self.connection, self.cursor = self.__create_connection()  # initiate the connection

    # create a new database connection
    def __create_connection(self):
        connection = None
        try:
            connection = sqlite3.connect("file::memory:?cache=shared", uri=True)
            return connection, connection.cursor()
        except Error as e:
            print(e)

    # create table if not exist
    def create_user_table(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS Users_table 
                        ([user_login] STRING PRIMARY KEY, [hashed_password] STRING UNIQUE, [salt] BLOB UNIQUE)''')
        self.connection.commit()

    # insert the data into the database
    def insert_data(self, login, password):
        salt, hashed_password = password_hashing.hash_password(password)
        self.cursor.execute('''INSERT INTO Users_table (user_login, hashed_password, salt)
                        VALUES
                        (?, ?, ?)
                        ''', (login, hashed_password, salt))
        self.connection.commit()

    # extract the data from database
    def extract_data(self, login):
        self.cursor.execute('''SELECT salt, hashed_password FROM Users_table
                                WHERE user_login = ?''', (login,))
        salt, hashed_password = self.cursor.fetchall()[0]
        return salt, hashed_password

    # output the data as dataframe
    def output_data(self):
        # read the table as dataframe using Pandas
        user_table = pd.read_sql('''SELECT user_login, hashed_password, salt FROM Users_table''', self.connection)
        return user_table
