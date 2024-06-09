import argparse
import base64
from hashlib import sha256
from Crypto.Cipher import AES

def encrypt(data, keyhash):
    cipher = AES.new(keyhash, AES.MODE_CFB) # creating cipher
    iv = bytes(cipher.iv)
    return base64.b64encode(iv + cipher.encrypt(data)) # encoding to pass iv with ease

def decrypt(enc_data, keyhash):
    enc_data = base64.b64decode(enc_data) # decoding and...
    iv = enc_data[:16] # strippng down iv
    cipher = AES.new(keyhash, AES.MODE_CFB, iv=iv) # creating (de)cipher 
    decrypted_data = cipher.decrypt(enc_data[16:])
    return decrypted_data # returning unencrypted bits

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
                    prog='pythocrypto',
                    description='program encrypts data in files\
                    using AES CFB encryption',
                    epilog='program will encrypt file and put \
                    encrypted contents to file with \".ecn\" \
                    extension. Please do not use \"-e\" and \"-d\"\
                    flags simultaneously.')

    parser.add_argument('filename', nargs=1, help='file to encrypt/decrypt')
    parser.add_argument('key', nargs=1, help='password')
    parser.add_argument('-e', '--encrypt', action='store_true',
                        help='encrypt any file.')
    parser.add_argument('-d', '--decrypt', action='store_true',
                        help='decrypt any file encrypted with this program')
    args = parser.parse_args()

    if args.encrypt and args.decrypt: # exception (why would anybody want to do that?)
        print("error: bad usage, can't use \"-e\" and \"-d\" at the same time")
        exit(-1)

    keyhash = sha256(args.key[0].encode()).digest() # using hashed key for convinience 

    with open(args.filename[0], "rb") as file_bin:
        data = file_bin.read()
        if args.encrypt:
            encrypted_data = encrypt(data, keyhash)
            with open(args.filename[0] + ".enc", "wb") as enc_file:
                enc_file.write(encrypted_data)
            print("Encryption complete.")
        elif args.decrypt:
            with open(args.filename[0], "rb") as enc_file:
                enc_data = enc_file.read()
                decrypted_data = decrypt(enc_data, keyhash)
                with open(args.filename[0] + ".dec", "wb") as dec_file:
                    dec_file.write(decrypted_data)
            print("Decryption complete.")

    exit(0)
