# -*- coding: utf-8 -*-
"""
Created on Thu Jan 18 16:18:53 2024

@author: edanc
"""

import re
import os


# A DICTIONARY FOR FILE TYPES -> {FILE TYPE: (SIGNATURE BYTES, SIGNATURE)}
FILES_SIGNATURES = {'png': (8, '89504E470D0A1A0A'),
                    'zip': (4, '504B0304'),
                    'exe': (2, '4D5A'),
                    'jpg': (3, 'FFD8FF'),
                    'jpeg': (3, 'FFD8FF'),
                    'pdf': (7, '255044462D312E')}

# A DICTIONARY FOR FILE SIZES IN KB -> {FILE TYPE: (MIN SIZE, MAX SIZE)}
FILES_SIZES = {'png': (5, 11000),
               'jpg': (5, 11000),
               'jpeg': (5, 11000),
               'pdf': (100, 21000)}

def get_file_signature(file_path, file_type):
    try:
        with open(file_path, 'rb') as file:
            
            
            #gets the signature's number of bytes
            sign_bytes = FILES_SIGNATURES[file_type][0]
            # Read the first signature bytes
            signature_bytes = file.read(sign_bytes)

            # Convert each byte to a hex string and concatenate
            signature_hex = ''.join(format(byte, '02X') for byte in signature_bytes)
            
            if signature_hex is not None:
                print(f"The file signature is: {signature_hex}")
            return signature_hex

    except Exception as e:
        print(f"Error: {e}")
        return None

    
def get_file_sizeKB(file_path):
    try:
        # Get the size of the file in bytes
        size_in_bytes = os.path.getsize(file_path)

        # Convert bytes to kilobytes
        size_in_kb = size_in_bytes / 1024

        return size_in_kb
    except FileNotFoundError:
        print(f"The file at {file_path} does not exist.")
        return None


def is_signature_match(file_path, file_type):
    signature = get_file_signature(file_path, file_type)
    
    if signature != FILES_SIGNATURES[file_type][1]:
        print("SIGNATURE DOES NOT MATCH.")
        return False
    
    print("SIGNATURE IS FINE :)")
    return True

def is_size_match(file_path, file_type):
    file_size = get_file_sizeKB(file_path)
    min_size = FILES_SIZES[file_type][0]
    max_size = FILES_SIZES[file_type][1]

    if file_size > max_size or file_size < min_size:
        print("SIZE DOES NOT MATCH.")
        return False
    print("SIZE IS FINE :)")
    return True


def is_file_sus(file_path):
    file_type = re.findall("\..+$", file_path)[0][1:]
    print("FILE TYPE: ", file_type)
    signature_check = is_signature_match(file_path, file_type)
    size_check = is_size_match(file_path, file_type)
    if signature_check and size_check:
        return False
    print("SUS FILE DETECTED!!!!")
    return True
    

file_path = r"C:\Users\edanc\Downloads\doc55.pdf"
is_file_sus(file_path)























