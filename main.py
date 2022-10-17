import base64
import datetime
import hashlib
import sys
import pyaes
import pbkdf2
import binascii
import os
import secrets
import os.path

password = 'khabao'


def ReadFile(fileName):
    base64Str = ""
    with open(fileName, 'rb') as binary_file:
        binary_file_data = binary_file.read()
        base64_encoded_data = base64.b64encode(binary_file_data)
        base64_message = base64_encoded_data.decode('utf-8')
        base64Str = base64_message
    return base64Str


# def WriteFile(fileName):


def newPassword():
    time = str(datetime.datetime.now().year)+str(datetime.datetime.now().month)+str(datetime.datetime.now().day) + \
        str(datetime.datetime.now().hour)+str(datetime.datetime.now().minute)
    newPassword = password+time
    print(newPassword)
    return newPassword


def Login():
    inputPass = input('Please enter password: ')
    if (inputPass == newPassword()):
        return True
    return False


def Encryption():
    password = newPassword()
    passwordSalt = os.urandom(16)
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    # Save ciphertext to file
    with open('key.bin', 'wb') as file_to_save:
        file_to_save.write(key)

    # print('AES encryption key:', binascii.hexlify(key))
    iv = secrets.randbits(256)
    with open('iv.txt', 'w') as file_to_save:
        file_to_save.write(str(iv))

    # print(type(ReadFile('logo.png')))
    plaintext = ReadFile('logo.png')
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    ciphertext = aes.encrypt(plaintext)
    # print('Encrypted:', binascii.hexlify(ciphertext))

    # Save ciphertext to file
    with open('ciphertext.bin', 'wb') as file_to_save:
        file_to_save.write(ciphertext)
    print("Mã hóa thành công")


def Decryption():
    # Read file to get ciphertext:
    ciphertext = ''
    if (os.path.isfile('ciphertext.bin') == False):
        print("Please Encryption before Deryption")
        return
    with open('ciphertext.bin', 'rb') as binary_file:
        ciphertext = binary_file.read()

    # Read file to get key:
    key = ''
    with open('key.bin', 'rb') as binary_file:
        key = binary_file.read()

    # Decrypt:
    iv = 0
    with open('iv.txt', 'r') as file_to_save:
        iv = int(file_to_save.read())

    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(iv))
    decrypted = aes.decrypt(ciphertext)
    # print('Decrypted: ', decrypted)
    # base64_img = ReadFile('logo.png')
    base64_img_bytes = decrypted.decode('utf-8')
    with open('decoded_image.png', 'wb') as file_to_save:
        decoded_image_data = base64.decodebytes(
            base64_img_bytes.encode('utf-8'))
        file_to_save.write(decoded_image_data)
    print("Giải mã thành công")


def Menu():
    print('1. Encryption')
    print('2. Decryption')
    print('3. Exit')
    print('-----------------')


def Menu2():
    print('1. Return Menu')
    print('Enter something else to exit. ')
    print('-----------------')


def Main():
    while (True):
        print('LOGIN: ')
        if (Login() == True):
            print('Login Successfully!')
            while (True):
                Menu()
                choice = input('Choice: ')
                if (choice == '1'):
                    if (Login()):
                        Encryption()
                        Menu2()
                        choice2 = int(input('Choice: '))
                        if (choice2 != 1):
                            break

                    else:
                        print('Incorrect Password')
                elif (choice == '2'):
                    if (Login()):
                        Decryption()
                        Menu2()
                        choice2 = input('Choice: ')
                        if (choice2 != '1'):
                            break

                    else:
                        print('Incorrect Password')
                elif (choice == '3'):
                    sys.exit()
        else:
            print('Incorrect Password')


# Run Main:
Main()
