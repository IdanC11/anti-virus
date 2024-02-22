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
import glob
#from concurrent.futures import ThreadPoolExecutor
import concurrent.futures

start_time = time.time()

CORES = 6

THREADS_NUM = 2 * CORES

BUFFER_SIZE = 8192

# A DICTIONARY FOR FILE TYPES -> {FILE TYPE: (SIGNATURE BYTES, SIGNATURE)}
FILES_SIGNATURES = {'png': (8, '89504E470D0A1A0A'),
                    'zip': (4, '504B0304'),
                    'exe': (2, '4D5A'),
                    'jpg': (3, 'FFD8FF'),
                    'jpeg': (3, 'FFD8FF'),
                    'pdf': (7, '255044462D312E'),
                    'mp4': (12, '000000186674797033677034')}

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

def get_file_type(file_path):
    file_type = re.search("(\.)(.+$)", file_path)
    if file_type == None:
        return None
    file_type = file_type.group(2)
    return file_type.lower()

class File:
    def __init__(self, path):
        self.file_path = path
        self.file_type = get_file_type(self.file_path)
        self.content = File.get_file_content(self)
        self.sha256 = File.calculate_hash(self, hashlib.sha256)
        self.md5 = File.calculate_hash(self, hashlib.md5)
        self.file_signature = File.get_file_signature(self)
        self.is_file_in_dict = File.file_in_dict(self)
        self.sizeKB = File.get_file_sizeKB(self)
        

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
            return False
        return True
    
    
    def is_signature_match(self):
        signature = self.file_signature
        if signature != FILES_SIGNATURES[self.file_type][1]:
            return False
        return True

    def is_size_match(self):
        file_size = self.sizeKB
        min_size = FILES_SIZES[self.file_type][0]
        max_size = FILES_SIZES[self.file_type][1]

        if file_size > max_size or file_size < min_size:
            return False
        return True
    
    
    def add_hashes_to_db(self):
        db_connection, db_cursor = connect_to_db()
        db_cursor.execute("INSERT OR IGNORE INTO hashes (file_path, sha256, md5) VALUES (?, ?, ?)"
                          ,(self.file_path, self.sha256, self.md5))
        
        db_connection.commit()
        
        db_connection.close()
    
    
    def get_file_sizeKB(self):
        try:
            # Get the size of the file in bytes
            size_in_bytes = os.path.getsize(self.file_path)

            # Convert bytes to kilobytes
            size_in_kb = size_in_bytes / 1024

            return size_in_kb
        except FileNotFoundError:
            print(f"The file at {self.file_path} does not exist.")
            return None
    
    def get_file_content(self):
        with open(self.file_path, 'rb') as f:
            content = b""
            while chunk := f.read(8192): # Read in 8KB chunks
                content += chunk
        return content
    
    
    def chunk_generator(self):
        start = 0
        while start < len(self.content):
            yield self.content[start : start + BUFFER_SIZE]
            start += BUFFER_SIZE
    
    def calculate_hash(self, hash_algorithm):
        if self.content is None:
            raise ValueError("File content not loaded. Call open_file() before calculating hash.")
        
        hash_obj = hash_algorithm()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(hash_obj.update, chunk) for chunk in self.chunk_generator()]
            concurrent.futures.wait(futures)  # Wait for all threads to finish

        return hash_obj.hexdigest()
    """
    def calculate_hash(self, hash_algorithm):
        hash_obj = hash_algorithm()
        hash_obj.update(self.content)
        return hash_obj.hexdigest()
    
    
    def get_file_content(self):
        with open(self.file_path, 'rb') as f:
            content = f.read()
        return content
        
    def calculate_hash(self, hash_algorithm):
        return hash_algorithm(self.content).hexdigest()

    
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
    """
    
    def get_file_signature(self):
        try:
            with open(self.file_path, 'rb') as file:                
                #gets the signature's number of bytes
                sign_bytes = FILES_SIGNATURES[self.file_type][0]
                # Read the first signature bytes
                signature_bytes = file.read(sign_bytes)

                # Convert each byte to a hex string and concatenate
                signature_hex = ''.join(format(byte, '02X') for byte in signature_bytes)
                
                return signature_hex

        except Exception as e:
            print(f"Error: {e}")
            return None
    
    def file_in_dict(file_type):
        if file_type in FILES_SIGNATURES.keys():
            return True
        return False
    
    def is_file_sus(self, db_connection, db_cursor):
        signature_check = File.is_signature_match(self)
        #signature_check = True #***************************************************
        size_check = File.is_size_match(self)
        #hashes_check = File.is_hashes_equal(self, db_connection, db_cursor)
        hashes_check = True #***************************************************
        if signature_check and size_check and hashes_check:
            print(f"{self.file_path}: FILE IS GOOD :)")
            return False
        print(f"{self.file_path}: SUS FILE DETECTED!!!!")
        return True
    
    
    def open_thread_to_is_file_sus(self):
        
        t = threading.Thread(target=self.is_file_sus)
        return t
    
    
"""
def get_files_in_folder(folder_path):
    all_files_in_folder = []
    for root, dirs, files in os.walk(folder_path, topdown=False):
       for name in files:
          file = os.path.join(root, name)
          f = File(file)
          f.add_hashes_to_db()
          all_files_in_folder.append(f)
    print(f"FILES COUNT = {len(all_files_in_folder)}")
    return all_files_in_folder       
"""

def get_files_in_folder(directory_path):
    files = glob.glob(os.path.join(directory_path, '**', '*'), recursive=True)
    files_objects = []
    for file in files:
        if get_file_type(file) == None:
            files.remove(file)
        else:
            f = File(file)
            files_objects.append(f)
    files.clear()
    print("GET FILES IN FOLDER FINISHED!!!!!!!!!!!!!!!")
    return files_objects

def files_count_in_thread(folder_path):
    files = get_files_in_folder(folder_path)
    files_amount = len(files)
    files_for_thread = files_amount / THREADS_NUM
    
    return files, int(files_for_thread)

def multiple_is_file_sus(files):
    db_connection, db_cursor = connect_to_db()
    for file in files:
        file.is_file_sus(db_connection, db_cursor)        
    db_connection.close()
    

def scan_files(folder_path):
    files, files_for_thread = files_count_in_thread(folder_path)
    threads = []
    groups = []
    files_group = []
    count_for_group = 0
    for f in files:
        if f.is_file_in_dict:
            if count_for_group < files_for_thread - 1:
                files_group.append(f)
                count_for_group += 1 
            else:
                files_group.append(f)
                groups.append(files_group)
                files_group = []
                count_for_group = 0
            
    for i in range(len(files_group)):
        groups[i].append(files_group[i])
    
    for group in groups:
        for file in group:
            print(file.file_path)
        print("------------------------------------------------------------")
    
    for group in groups:
        t = threading.Thread(target=multiple_is_file_sus, args=[group])
        t.start()
        threads.append(t)
    
    for thread in threads:
        thread.join()
    
    print("SCAN FINISHED!!!!!!!!!!")
    return files
 

folder_path = r"D:\PicsForProject"    
files = scan_files(folder_path)

# Record the end time
end_time = time.time()

# Calculate the runtime
runtime = end_time - start_time

# Print the result
print(f"Program executed in {runtime} seconds")
 
        
        
        
        
