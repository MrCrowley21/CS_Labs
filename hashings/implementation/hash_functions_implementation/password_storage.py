from implementation.hash_functions_implementation.components_implementation.data_base_manipulator import *
from implementation.hash_functions_implementation.components_implementation.password_hashing import *


class PasswordStorage:
    def __init__(self):
        self.data_base = DataBase()  # initialize the database
        self.password_hashing = PasswordHashing()  # initialize the password hashing
        self.data_base.create_user_table()  # create the database table

    # insert the new user into the database
    def insert_new_password(self, user, password):
        # insert the user
        self.data_base.insert_data(user, password)
        print('A new user has been added successfully! Current database state:')
        # output the current state of the database table
        database_state = self.data_base.output_data()
        return database_state

    # verify if user introduces the right password
    def verify_user_password(self, user, input_password):
        # get the salt and the password of the corresponded user from the database
        salt, hashed_password = self.data_base.extract_data(user)
        # verify the current password with the one from the database
        verification = password_hashing.verify_password(input_password, salt, hashed_password)
        if verification:
            return f'Successful attempt!'
        else:
            return f'Attempt failed! You introduced a wrong password for user {user}'
