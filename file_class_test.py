# -*- coding: utf-8 -*-
"""
Created on Wed Jan 31 12:50:22 2024

@author: edanc
"""


import re
import hashlib
import sqlite3
import os
import threading
import time


start_time = time.time()


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

def connect_to_db():
    connection = sqlite3.connect("file_hashes.db")
    cursor = connection.cursor()
    return (connection, cursor)

def close_db_connection(connection):
    connection.close()


class File:
    def __init__(self, path):
        self.file_path = path
        self.file_type = File.get_file_type(self.file_path)
        self.sha256 = File.calculate_sha256(self.file_path)
        self.md5 = File.calculate_md5(self.file_path)
        self.file_signature = File.get_file_signature(self.file_path, self.file_type)
        self.is_file_in_dict = File.file_in_dict(self.file_type)
        self.sizeKB = File.get_file_sizeKB(self.file_path)
        

    def get_hash_from_db(self, db_connection, db_cursor):
        db_cursor.execute("SELECT sha256, md5 FROM hashes WHERE file_path = ?", (self.file_path,))
        
        result = db_cursor.fetchone()
        
        if result:
            sha256, md5 = result
            return sha256, md5
        return None, None
    
    def is_hashes_equal(self, db_connection, db_cursor):
        current_sha256 = self.sha256
        current_md5 = self.md5
        
        original_sha256, original_md5 = File.get_hash_from_db(self, db_connection, db_cursor)
        
        if current_sha256 != original_sha256 and current_md5 != original_md5:
            #print("hashes does not match!!!")
            return False
        #print("HASHES ARE FINE :)")
        return True
    
    def is_signature_match(self):
        signature = self.file_signature
        
        if signature != FILES_SIGNATURES[self.file_type][1]:
            #print("SIGNATURE DOES NOT MATCH.")
            return False
        
        #print("SIGNATURE IS FINE :)")
        return True

    def is_size_match(self):
        file_size = self.sizeKB
        min_size = FILES_SIZES[self.file_type][0]
        max_size = FILES_SIZES[self.file_type][1]

        if file_size > max_size or file_size < min_size:
            #print("SIZE DOES NOT MATCH.")
            return False
        #print("SIZE IS FINE :)")
        return True
    
    def add_hashes_to_db(self):
        db_connection, db_cursor = connect_to_db()
        db_cursor.execute("""INSERT OR IGNORE INTO hashes (file_path, sha256, md5)
                       VALUES (?, ?, ?)
                       """,
                       (self.file_path, self.sha256, self.md5))
        
        db_connection.commit()
        
        db_connection.close()
        
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
    
    def get_file_type(file_path):
        file_type = re.search("(\.)(.+$)", file_path)
        file_type = file_type.group(2)
        return file_type.lower()
    
    def calculate_sha256(file_path):
        # Create a SHA-256 hash object
        sha256_hash = hashlib.sha256()

        # Open the file in binary mode and read chunks
        with open(file_path, "rb") as file:
            chunk = 0
            while chunk := file.read(8192):  # Read in 8KB chunks
                sha256_hash.update(chunk)

        # Get the hexadecimal representation of the hash
        sha256_hex_digest = sha256_hash.hexdigest()
        return sha256_hex_digest
    
    def calculate_md5(file_path):
        # Create an MD5 hash object
        md5_hash = hashlib.md5()

        # Open the file in binary mode and read chunks
        with open(file_path, "rb") as file:
            chunk = 0
            while chunk := file.read(8192):  # Read in 8KB chunks
                md5_hash.update(chunk)

        # Get the hexadecimal representation of the hash
        md5_hex_digest = md5_hash.hexdigest()
        return md5_hex_digest
    
    
    def get_file_signature(file_path, file_type):
        try:
            with open(file_path, 'rb') as file:                
                #gets the signature's number of bytes
                sign_bytes = FILES_SIGNATURES[file_type][0]
                # Read the first signature bytes
                signature_bytes = file.read(sign_bytes)

                # Convert each byte to a hex string and concatenate
                signature_hex = ''.join(format(byte, '02X') for byte in signature_bytes)
                
                #if signature_hex is not None:
                    #print(f"The file signature is: {signature_hex}")
                return signature_hex

        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def file_in_dict(file_type):
        if file_type in FILES_SIGNATURES.keys():
            return True
        return False
    
    def is_file_sus(self):
        db_connection, db_cursor = connect_to_db()
        signature_check = File.is_signature_match(self)
        size_check = File.is_size_match(self)
        hashes_check = File.is_hashes_equal(self, db_connection, db_cursor)
        db_connection.close()
        if signature_check and size_check and hashes_check:
            print(f" {self.file_path}: FILE IS GOOD :)")
            return False
        print("SUS FILE DETECTED!!!!")
        return True
    
    def open_thread_to_is_file_sus(self):
        
        t = threading.Thread(target=self.is_file_sus)
        return t
    
    

def get_files_in_folder(folder_path):
    all_files_in_folder = []
    for root, dirs, files in os.walk(folder_path, topdown=False):
       for name in files:
          file = os.path.join(root, name)
          f = File(file)
          f.add_hashes_to_db()
          #print(file)
          all_files_in_folder.append(f)
    return all_files_in_folder       
        

def scan_files(folder_path):
    files = get_files_in_folder(folder_path)
    threads = []
    for f in files:
        if f.is_file_in_dict:
            #print(file)
            t = f.open_thread_to_is_file_sus()
            t.start()
            threads.append(t)
            #is_file_sus(file)
    for thread in threads:
        thread.join()
    #for scan in scans:
     #   print(scan)
     
    return files
        

folder_path = r"C:\Users\edanc\OneDrive\Pictures\Slovenia-Croatia-2017"    
files = scan_files(folder_path)

# Record the end time
end_time = time.time()

# Calculate the runtime
runtime = end_time - start_time

# Print the result
print(f"Program executed in {runtime} seconds")
 
        
        
        
        
