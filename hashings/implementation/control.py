# class that contains selecting methods
class Control:
    # select the cipher to be used
    def get_action(self):
        print('Choose the number that corresponds to the action you want to perform:\n'
              '1 - Password Hashing\n'
              '2 - Digital Signature\n')
        action = int(input())
        if action not in range(1, 3):
            raise Exception('You should choose an integer between 1 and 2')
        return action

# select the action to be performed
    def get_activity(self, action_nr):
        if action_nr == 1:
            activity_1 = 'Register'
            activity_2 = 'Verify password'
        else:
            activity_1 = 'Sign'
            activity_2 = 'Verify signature'
        print('Choose the action you want to perform:\n'
              f'1 - {activity_1}\n'
              f'2 - {activity_2}')
        action = int(input())
        if action not in range(1, 3):
            raise Exception('You should choose an integer between 1 and 2')
        return action

    # return the string representing the necessary function
    def perform_activity(self, action, activity):
        if action == 1:
            print('Input the user name')
            user_name = input()
            print('Input the password')
            password = input()
            if activity == 1:
                return f'insert_new_password([user~{user_name} / password~{password}])'
            else:
                return f'verify_user_password([user~{user_name} / input_password~{password}])'
        elif action == 2 and activity == 1:
            print('Input the document to sign')
            document = input()
            return f'digital_sign_document([document~{document}])'
        elif action == 2 and activity == 2:
            print('Input the signed document')
            document = input()
            return f'verify_digital_signature([document~{document}])'

