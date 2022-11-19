from implementation.hash_functions_implementation.password_storage import *
from implementation.digital_signatures_implementation.digital_signature import *
from implementation.control import *

control = Control()
password_storage = PasswordStorage()
digital_signature = DigitalSignature()

while True:
    action_nr = control.get_action()
    if action_nr == 1:
        action = password_storage
    else:
        action = digital_signature

    # call function from the string
    activity_nr = control.get_activity(action_nr)
    function_name, arguments = control.perform_activity(action_nr, activity_nr).split('([')
    arguments_dict = dict()
    arguments_index = arguments.split(' / ')
    arguments_index[-1] = arguments_index[-1].replace('])', '')
    for item in arguments_index:
        argument_name, argument_value = item.split('~')
        arguments_dict.update({argument_name: argument_value})
    function = getattr(action, function_name)
    print(function(**arguments_dict))

