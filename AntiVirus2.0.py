# -*- coding: utf-8 -*-
"""
Created on Sun May 26 12:51:40 2024

@author: edanc
"""

import tkinter as tk
from tkinter import filedialog, ttk
import antiviruslib as av

def check_categories(file, points_reasons, DB_FILE):
    if not av.is_size_match(file.sizeKB, file.file_type):
        reason = "size"
        if reason not in points_reasons:
            points_reasons.append(reason)
    if not DB_FILE.is_hashes_equal(file, file.sha256, "sha256"):
        reason = "sha256"
        if reason not in points_reasons:
            points_reasons.append(reason)
    if not DB_FILE.is_hashes_equal(file, file.md5, "md5"):
        reason = "md5"
        if reason not in points_reasons:
            points_reasons.append(reason)
    if not av.is_signature_match(file.signature, file.file_type):
        reason = "signature"
        if reason not in points_reasons:
            points_reasons.append(reason)
    if av.is_virus_signature_in_file(file.content, DB_FILE):
        reason = "virus signature"
        if reason not in points_reasons:
            points_reasons.append(reason)
    if av.is_file_contains_malicious_code(file.file_path, DB_FILE):
        reason = "malicious code"
        if reason not in points_reasons:
            points_reasons.append(reason)

def scan_file(path):
    try:
        file = av.File(path)
        DB_FILE = av.DB_File("file_hashes.db")
        points_reasons = []

        check_categories(file, points_reasons, DB_FILE)
        
        if "exe" in file.file_type:
            file_name = file.file_path
            server_ip = "192.168.76.128"
            server_port = 12345
            av.send_file(file_name, server_ip, server_port)
            exe_status = av.receive_exe_status()
            if exe_status == b"1":
                points_reasons.append("Registry Changed")
            save_path = file.file_path
            listen_ip = "0.0.0.0"
            listen_port = 12347
            av.receive_file(save_path, listen_ip, listen_port)
            ret_file = av.File(save_path)
            check_categories(ret_file, points_reasons, DB_FILE)
            print("SECOND CHECK DONE!!!!!!!!!!!")
        
        DB_FILE.close_db_connection()
        status = "Malicious" if points_reasons else "Ok"
        reason = ', '.join(points_reasons) if points_reasons else "No issues found"

        return file.file_path, status, reason
    except Exception as e:
        print(e)
        return path, "Error", str(e)



class FileScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Scanner")
        self.root.geometry("800x600")
        self.root.resizable(False, False)  # Disable resizing
        self.create_widgets()
        
    def create_widgets(self):
        # File entry and button
        self.files_label = tk.Label(self.root, text="Select files:")
        self.files_label.grid(row=0, column=0, padx=10, pady=5)
        self.files_entry = tk.Entry(self.root, width=70)
        self.files_entry.grid(row=0, column=1, padx=10, pady=5)
        self.files_button = tk.Button(self.root, text="Browse", command=self.browse_files)
        self.files_button.grid(row=0, column=2, padx=10, pady=5)
        
        # Scan button
        self.scan_button = tk.Button(self.root, text="Scan File", command=self.scan_files)
        self.scan_button.grid(row=1, column=0, columnspan=3, pady=10)
        
        # Results table
        self.tree = ttk.Treeview(self.root, columns=("Path", "Status", "Reason"), show='headings')
        self.tree.heading("Path", text="File Path")
        self.tree.heading("Status", text="File Status")
        self.tree.heading("Reason", text="Reason")
        
        self.tree.column("Path", width=400)
        self.tree.column("Status", width=100)
        self.tree.column("Reason", width=250)
        
        self.tree.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky='nsew')
        
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
    def browse_files(self):
        file_paths = filedialog.askopenfilenames()
        if file_paths:
            self.files_entry.delete(0, tk.END)
            self.files_entry.insert(0, ';'.join(file_paths))
            
    def scan_files(self):
        # Get file paths from entry
        file_paths = self.files_entry.get().split(';')
        
        # Scan files and update table
        for file_path in file_paths:
            if file_path:
                path, status, reason = scan_file(file_path)
                self.tree.insert('', 'end', values=(path, status, reason))


root = tk.Tk()
app = FileScannerApp(root)
root.mainloop()
