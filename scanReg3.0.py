# -*- coding: utf-8 -*-
"""
Created on Thu May 30 21:22:43 2024

@author: Idan
"""

# -*- coding: utf-8 -*-
"""
Created on Sun May  5 20:56:07 2024

@author: edanc
"""

import winreg
import time
import json
import threading
import os
import hashlib
import socket
import subprocess
import ctypes
import sys


start_time = time.time()


def run_as_admin(exe_path):
    """
    Run a .exe file as administrator.

    :param exe_path: The path to the .exe file.
    """
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

    if is_admin:
        try:
            result = subprocess.run([exe_path], check=True)
            print(f"Execution result: {result}")
        except subprocess.CalledProcessError as e:
            print(f"Error: {e}")
    else:
        try:
            params = " ".join([exe_path] + sys.argv[1:])
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        except Exception as e:
            print(f"Failed to elevate to administrator: {e}")


def send_message(server_host='192.168.50.12', server_port=65432, message=""):
    """
    Connects to the server and sends a string.
    
    :param server_host: The hostname or IP address of the server.
    :param server_port: The port number of the server.
    :param message: The string message to send.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_host, server_port))
        s.sendall(message.encode())
        print(f"Sent message: {message}")

def receive_file(save_path, listen_ip, listen_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((listen_ip, listen_port))
            s.listen(1)
            print(f"Listening on {listen_ip}:{listen_port}...")

            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                with open(save_path, 'wb') as f:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        f.write(data)
                print(f"File received and saved to {save_path}.")
    except Exception as e:
        print(f"Failed to receive file: {e}")

def send_file(file_name, server_ip, server_port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, server_port))
            with open(file_name, 'rb') as f:
                data = f.read()
                s.sendall(data)
            print(f"File {file_name} sent successfully.")
    except Exception as e:
        print(f"Failed to send file: {e}")

#EXE_FILE_TO_RUN = r"C:\Users\edanc\output\AddKeyToReg.exe"
def run_exe_file(file_path):
    os.startfile(file_path)

class ScanReg():
    def __init__(self):
        self.REG_HKEYS = {
                         winreg.HKEY_CURRENT_CONFIG : (r"HKEY_CURRENT_CONFIG_before.json", r"HKEY_CURRENT_CONFIG_after.json")}
        self.EXCLUDE_KEYS = [
            r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\OneDrive\Accounts",
            r"HKEY_PERFORMANCE_DATA",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Hardware Profiles",
            r"HKEY_LOCAL_MACHINE\SYSTEM\MountedDevices",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Volatile Environment",
            r"HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\0018C0031735A98A\\1044477\\",
            r"HKEY_USERS\\S-1-5-18\\Software\\Microsoft\\Office\\16.0\\Common\\ClientTelemetry\\RulesLastModified\\",
            r"HKEY_USERS\\S-1-5-18\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\0018C0031735A98A\\1044477\\",
            r"HKEY_USERS\\.DEFAULT\\Software\\Microsoft\\Office\\16.0\\Common\\ClientTelemetry\\RulesLastModified\\",
            r"HKEY_CLASSES_ROOT\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\Microsoft.Windows.ShellExperienceHost_cw5n1h2txyewy\\HAM\\AUI\\App\\V1\\LU\\",
            r"HKEY_CLASSES_ROOT\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\Microsoft.YourPhone_8wekyb3d8bbwe\\HAM\\AUI\\App\\V1\\LU\\",
            r"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\OneDrive\\Accounts\\",
            r"HKEY_CURRENT_USER\\SOFTWARE\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppModel\\SystemAppData\\Microsoft.YourPhone_8wekyb3d8bbwe\\HAM\\AUI\\App\\V1\\LU\\"
        ]
        
        self.HKEYS_HANDLES = {}
        for hkey in self.REG_HKEYS.keys():
            handle = winreg.OpenKey(hkey, None, 0, winreg.KEY_READ)
            self.HKEYS_HANDLES[hkey] = handle
            
        self.BEFORE = 0
        self.AFTER = 1

    def open_all_files(self, condition, access):
        # condition is an integer that indicates if the programm is before or after the .exe file has ran
        # access is a string that specifices how to open the file
        opened_files = {}
        for hkey in self.REG_HKEYS.keys():
            file_to_open = self.REG_HKEYS[hkey][condition]
            open_file = open(file_to_open, access)
            opened_files[hkey] = open_file
        return opened_files

    def close_all_files(self, opened_files):
        for file in opened_files:
            file.close()

    def write_to_json(self, json_file, dict_obj):
        json.dump(dict_obj, json_file)

    def get_key_values(self, key_handle):
        values = []
        index = 0
        while True:
            try:
                value = winreg.EnumValue(key_handle, index)
                # Try decoding using UTF-8, fallback to latin1 if it fails
                if isinstance(value[1], bytes):
                    try:
                        value = (value[0], value[1].decode('utf-8'), value[2])
                    except UnicodeDecodeError:
                        value = (value[0], value[1].decode('latin1'), value[2])
                values.append(value)
                index += 1
            except OSError as e:
                if e.winerror == 259:  # No more data
                    break
        return values

    def scan_hkey(self, hkey ,key_handle, key_path_string, json_file):
        index = 0
        while True:
            try:
                subkey = winreg.EnumKey(key_handle, index)
                sub_key_string = key_path_string + str(subkey) + "\\"
                if sub_key_string in self.EXCLUDE_KEYS:
                    continue
                index += 1
                sub_key_handle = winreg.OpenKey(hkey, sub_key_string, 0 , winreg.KEY_READ)
                subkey_dict = {}
                subkey_dict[sub_key_string] = self.get_key_values(sub_key_handle)
                self.write_to_json(json_file, subkey_dict)
                self.scan_hkey(hkey, sub_key_handle, sub_key_string, json_file)
            except OSError as e:
                if e.winerror == 259:  # No more data
                    break
                elif e.winerror == 5:  # Access denied
                    print("Permission denied to access subkey:", sub_key_string)
                else:
                    raise

    def scan_registry(self, condition):
        # condition is an integer that indicates if the programm is before or after the .exe file has ran
        opened_files = self.open_all_files(condition, "w")
        threads = []
        for hkey in self.REG_HKEYS:
            t = threading.Thread(target=self.scan_hkey, args=(hkey, self.HKEYS_HANDLES[hkey], "", opened_files[hkey]))
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        return opened_files
    
    def compare_scan_results(self, exe_file):
        files_before_exe = self.scan_registry(self.BEFORE)
        self.close_all_files(files_before_exe.values())

        run_as_admin(exe_file)

        files_after_exe = self.scan_registry(self.AFTER)
        self.close_all_files(files_after_exe.values())
        
        files_before_exe = self.open_all_files(self.BEFORE, "r")
        files_after_exe = self.open_all_files(self.AFTER, "r")

        for hkey in files_before_exe:
            file_before = files_before_exe[hkey]
            file_after = files_after_exe[hkey]
            content_before = file_before.read()
            content_after = file_after.read()
            hash_before = hashlib.sha256(content_before.encode()).hexdigest()
            hash_after = hashlib.sha256(content_after.encode()).hexdigest()
            if hash_before != hash_after:
                return False
        return True


while True:
    save_path = r"C:\Users\Idan\Downloads\FileToRun.exe"  # Replace with where you want to save the file
    listen_ip = "0.0.0.0"  # Use 0.0.0.0 to listen on all interfaces
    listen_port = 12345  # The same port as used in the sender script

    receive_file(save_path, listen_ip, listen_port)


    scan_reg = ScanReg()

    check = scan_reg.compare_scan_results(save_path)
    if check:
        send_message(message="0")
        print("File is Fine!!!!")
    else:
        send_message(message="1")
        print("File is Malicious!!!!!!!")
    send_file(save_path, "192.168.50.12", 12347)
    print("SENT FILE!!!!!!!!")

end_time = time.time()

# Calculate the runtime
runtime = end_time - start_time

print(f"Program executed in {runtime} seconds")





