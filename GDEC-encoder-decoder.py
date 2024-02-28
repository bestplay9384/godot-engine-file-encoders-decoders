from Crypto.Cipher import AES
import hashlib
import os, struct
import argparse

def generate_key(password):
    hash = hashlib.md5(password.encode()).digest()
    return bytes(hash.hex(), 'utf-8')

def pad(data):
    return data + b'\0' * (16 - len(data) % 16)

def decrypt(input_file, output_file, password):
    with open(input_file, 'rb') as file, open(output_file, 'wb') as out_file:
        header = file.read(4);
        if header.decode() != "GDEC":
            print("Incorrect file format")
            
            return

        file_mode = struct.unpack('<I', file.read(4))[0]
        if file_mode != 1:
            print("Incorrect file format. Is this from Godot 3.6 or less?")
            
            return

        file_hash = file.read(16)
        data_size = struct.unpack('<Q', file.read(8))[0]
        block_count = (data_size + 15) >> 4
        padding = block_count * 16 - data_size

        key = generate_key(password)
        cipher = AES.new(key, AES.MODE_ECB)
        hash = hashlib.md5()

        for i in range(block_count - 1):
            block_bytes = file.read(16)
            dcry_bytes = cipher.decrypt(block_bytes)
            out_file.write(dcry_bytes)
            hash.update(dcry_bytes)
    
        block_bytes = file.read(16)
        dcry_bytes = cipher.decrypt(block_bytes)
        out_file.write(dcry_bytes[:16-padding])
        hash.update(dcry_bytes[:16-padding])

        final_hash = hash.digest()

        if file_hash == final_hash:
            print("Done!")
        else:
            print("Failed!")

def encrypt(input_file, output_file, password):
    with open(input_file, 'rb') as file, open(output_file, 'wb') as out_file:
        out_file.write(b"GDEC")
        out_file.write(struct.pack('<I', 1))

        hash = hashlib.md5()
        while chunk := file.read(8192):
            hash.update(chunk)
        file_hash = hash.digest()
        out_file.write(file_hash)

        file.seek(0)
        data_size = os.path.getsize(input_file)
        data_size_bytes = struct.pack('<Q', data_size)
        out_file.write(data_size_bytes)

        block_count = (data_size + 15) >> 4
        key = generate_key(password)

        cipher = AES.new(key, AES.MODE_ECB)
        for i in range(block_count):
            block_bytes = file.read(16)
            if len(block_bytes) < 16:
                block_bytes = pad(block_bytes)
            encry_bytes = cipher.encrypt(block_bytes)
            out_file.write(encry_bytes)

    print("Done!")

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a Godot <= 3.6 password protected file.')
    parser.add_argument('action', choices=['enc', 'dec'], help='The action to perform. "enc" to encrypt, "dec" to decrypt.')
    parser.add_argument('input_file', help='The input file path.')
    parser.add_argument('output_file', help='The output file path.')
    parser.add_argument('password', help='The password to use for encryption/decryption.')

    args = parser.parse_args()

    if args.action == 'enc':
        encrypt(args.input_file, args.output_file, args.password)
    elif args.action == 'dec':
        decrypt(args.input_file, args.output_file, args.password)

if __name__ == "__main__":
    main()