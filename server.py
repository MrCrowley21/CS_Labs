import pyotp
import requests
from flask import Flask, request, jsonify, redirect, url_for
from flask_httpauth import HTTPBasicAuth
from base64 import b64encode

from hashings.implementation.hash_functions_implementation.components_implementation.password_hashing import *
from ciphers.symmetric_ciphers.classical_ciphers.implementation.cipher_implementation.caesar_cipher_permutation import *
from ciphers.symmetric_ciphers.classical_ciphers.implementation.cipher_implementation.vigenere_cipher import *
from ciphers.symmetric_ciphers.classical_ciphers.implementation.cipher_implementation.bifid_cipher import *
from ciphers.symmetric_ciphers.classical_ciphers.implementation.cipher_implementation.playfair_cipher import *
from ciphers.symmetric_ciphers.stream_ciphers.implementation.cipher_implementation.des_cipher import *
from ciphers.symmetric_ciphers.stream_ciphers.implementation.cipher_implementation.grain_cipher import *
from email_manipulator.email_sender import *

# set the loggings
logging.basicConfig(level=logging.DEBUG)

# define server's instances
app = Flask(__name__)
auth = HTTPBasicAuth()

# import global classes
password_hashing = PasswordHashing()
email_manipulator = EmailManipulator()

# define users' characteristics
users = {}
headers = {}
roles = {"unknown": {"access_list": []},
         "victorian": {"access_list": ['Caesar Cipher with Permutation', 'Bifid Cipher', 'Playfair Cipher',
                                       'Vigenere Cipher']},
         "millennial": {"access_list": ['Caesar Cipher with Permutation', 'Bifid Cipher', 'Playfair Cipher',
                                        'Vigenere Cipher', "DES", "Grain Cipher"]}}


# verify the basic password (token generated with basic login)
@auth.verify_password
def verify_password(username, password):
    if username in users and \
            password_hashing.verify_password(password, users.get(username)['salt'], users.get(username)['password']):
        return username


# define register function
@app.route('/register', methods=['POST'])
def register_user():
    user_info = request.json
    try:
        username = user_info["username"]
        password = user_info["password"]
        email = user_info["email"]
        role = user_info["role"]
        if not (username in users):
            salt, hashed_password = password_hashing.hash_password(password)
            users[username] = {'salt': salt, 'password': hashed_password, 'email': email, 'role': role}
            logging.info(f'{users}')
            return 'The user has been successfully registered!'
        else:
            logging.warning(f'Duplicate username')
            return 'User with this username already exists. Please, choose another username!'
    except:
        logging.warning(f'Wrong registration format')
        return f'Wrong data for user registration!'


# define basic login function
@app.route('/basic_login', methods=['POST', 'GET'])
def login_basic():
    if request.method == 'POST' or request.method == 'GET':
        user_details = request.json
        username = user_details["username"]
        password = user_details["password"]
        if username in users:
            basic_token = b64encode(f"{username}:{password}".encode('utf-8')).decode("ascii")
            headers['Authorization'] = basic_token
            return jsonify({username: basic_token})
        else:
            logging.warning(f'No valid user')
            return jsonify(f'Invalid data provided')


# define multi-factor authentication function
@app.route('/multi_factor_login', methods=['POST'])
def login_mfa():
    user_details = request.json
    username = user_details["username"]
    password = user_details["password"]
    basic_auth_token = requests.get('http://192.168.0.26:8080/basic_login',
                                    json={'username': username, 'password': password}).json()
    print(basic_auth_token)
    if basic_auth_token[username]:
        user = users[username]
        generate_otp_code(username)
        while not ('otp_auth' in users[username]) or user['otp_auth']['validation'] is None:
            pass
        if user['otp_auth']['validation']:
            return jsonify({username: basic_auth_token[username]})
        else:
            return jsonify(f'Logging attempt failed')
    else:
        logging.warning(f'No valid user')
        return jsonify(f'Invalid data provided')


# define the otp_authentication verification
@app.route('/otp_login/<username>', methods=['POST'])
def login_otp(username):
    secret_code = users[username]['otp_auth']['secret']
    data = request.json
    otp_data = data['otp']
    if pyotp.TOTP(secret_code, interval=180).verify(otp_data):
        users[username]['otp_auth']['validation'] = True
        return jsonify(f'Logged in successfully')
    else:
        users[username]['otp_auth']['validation'] = False
        return jsonify(f'Invalid data provided')


# load the data and perform ciphers
@app.route('/encryption_algorithms', methods=['GET', 'POST'])
@auth.login_required
def get_ciphers():
    if request.method == 'GET':
        if users[auth.current_user()]['role'] in roles:
            return jsonify(f'Available ciphers: {roles[users[auth.current_user()]["role"]]["access_list"]}')
        else:
            return jsonify({'Available ciphers': None})
    elif request.method == 'POST':
        choice = request.json
        cipher_name = choice["cipher"]
        if cipher_name == 'DES':
            return redirect(url_for('perform_des'), code=307)
        elif cipher_name == 'Grain Cipher':
            return redirect(url_for('perform_grain'), code=307)
        elif cipher_name == 'Caesar Cipher with Permutation':
            return redirect(url_for('perform_caesar'), code=307)
        elif cipher_name == 'Bifid Cipher':
            return redirect(url_for('perform_bifid'), code=307)
        elif cipher_name == 'Playfair Cipher':
            return redirect(url_for('perform_playfair'), code=307)
        elif cipher_name == 'Vigenere Cipher':
            return redirect(url_for('perform_vigenere'), code=307)


# perform Caesar Cipher with permutation
@app.route('/Caesar_permutation_cipher', methods=['POST'])
@auth.login_required
def perform_caesar():
    if "Caesar Cipher with Permutation" in roles[users[auth.current_user()]['role']]["access_list"]:
        choice = request.json
        operation = choice["operation"]
        key = choice["key"]
        shift_key = choice["shift_key"]
        text = choice["text"]
        return perform_cipher_operation(operation, CaesarCipherPermutation, [key, shift_key, text])
    else:
        return jsonify(f'Unauthorized access')


# perform Bifid Cipher
@app.route('/Bifid_cipher', methods=['POST'])
@auth.login_required
def perform_bifid():
    if "Bifid Cipher" in roles[users[auth.current_user()]['role']]["access_list"]:
        choice = request.json
        operation = choice["operation"]
        key = choice["key"]
        keyword = choice["keyword"]
        text = choice["text"]
        return perform_cipher_operation(operation, BifidCipher, [keyword, key, text])
    else:
        return jsonify(f'Unauthorized access')


# perform Vigenere Cipher
@app.route('/Vigenere_cipher', methods=['POST'])
@auth.login_required
def perform_vigenere():
    if "Vigenere Cipher" in roles[users[auth.current_user()]['role']]["access_list"]:
        choice = request.json
        operation = choice["operation"]
        keyword = choice["keyword"]
        text = choice["text"]
        return perform_cipher_operation(operation, VigenereCipher, [keyword, text])
    else:
        return jsonify(f'Unauthorized access')


# perform Playfair Cipher
@app.route('/Playfair_cipher', methods=['POST'])
@auth.login_required
def perform_playfair():
    if "Playfair Cipher" in roles[users[auth.current_user()]['role']]["access_list"]:
        choice = request.json
        operation = choice["operation"]
        keyword = choice["keyword"]
        text = choice["text"]
        return perform_cipher_operation(operation, PlayfairCipher, [keyword, text])
    else:
        return jsonify(f'Unauthorized access')


# perform DES
@app.route('/DES_cipher', methods=['POST'])
@auth.login_required
def perform_des():
    if "DES" in roles[users[auth.current_user()]['role']]["access_list"]:
        choice = request.json
        operation = choice["operation"]
        key = choice["key"]
        text = choice["text"]
        return perform_cipher_operation(operation, DESCipher, [key, text])
    else:
        return jsonify(f'Unauthorized access')


# perform Grain Cipher
@app.route('/Grain_cipher', methods=['POST'])
@auth.login_required
def perform_grain():
    if "Grain Cipher" in roles[users[auth.current_user()]['role']]["access_list"]:
        choice = request.json
        operation = choice["operation"]
        key = choice["key"]
        iv = choice["iv"]
        text = choice["text"]
        return perform_cipher_operation(operation, GrainCipher, [key, iv, text])
    else:
        return jsonify(f'Unauthorized access')


# help function to generate otp code and send it via email
def generate_otp_code(username):
    secret_code = pyotp.random_base32()
    totp = pyotp.TOTP(secret_code, interval=180)
    code = totp.now()
    email_manipulator.send_email(users.get(username)["email"], code)
    users[username]['otp_auth'] = {'secret': secret_code, 'validation': None}
    return secret_code


# help function to choose the type of operation to perform over the cipher
def perform_cipher_operation(operation, cipher, parameter_list):
    if operation == 'Encrypt':
        result = cipher(*parameter_list).encrypt_text()
    else:
        result = cipher(*parameter_list).decrypt_text()
    return jsonify({'Result': result})


if __name__ == "__main__":
    # run the server
    app.run(port=8080, host="0.0.0.0", debug=True, use_reloader=False)
