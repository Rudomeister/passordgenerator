import tkinter as tk
import string
import random
import os
from cryptography.fernet import Fernet


# Get the directory containing the script
script_dir = os.path.dirname(__file__)


# --- Key Management ---

def show_key_popup(key):
    # Create a new popup window
    popup = tk.Toplevel(window)
    popup.title("Din unike nøkkel")
    popup.lift()
    popup.focus_set()
    popup.grab_set()

    # Add a label to display the key
    key_label = tk.Label(popup, text=key.decode())
    key_label.pack(pady=20)

    # Function to copy the key to clipboard
    def copy_key_to_clipboard():
        popup.clipboard_clear()
        popup.clipboard_append(key.decode())

    # Add a button to copy the key to clipboard
    copy_button = tk.Button(popup, text="Kopier nøkkel", command=copy_key_to_clipboard)
    copy_button.pack(pady=20)

    # Add a label with instructions
    instructions = tk.Label(popup, text="Vennligst ta en sikkerhetskopi av denne nøkkelen og oppbevar den på et sikkert sted.")
    instructions.pack(pady=20)
        # Function to close the window and show the main window
    def close_and_show_main():
        popup.destroy()
        window.deiconify()  # Gjenoppretter hovedvinduet
        
    # Function to close the window
    close_button = tk.Button(popup, text="Lukk dette vinduet", command=close_and_show_main)
    close_button.pack(pady=20)

def get_key():
    KEY_FILE = os.path.join(script_dir, "appkey.key")
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        show_key_popup(key)
        return key    

# Create the main window
window = tk.Tk()
window.title("Passordgenerator")
if not os.path.exists(os.path.join(script_dir, "appkey.key")):
    window.withdraw()  # Skjul hovedvinduet i stedet for å minimere det
    
key = get_key()
cipher_suite = Fernet(key)

# --- Password Management ---

def generate_password(length, use_lowercase, use_uppercase, use_digits, use_symbols):
    characters = ''
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        raise ValueError('No character set selected')

    return ''.join(random.choice(characters) for _ in range(length))

def save_encrypted_password(password):
    encrypted_password = cipher_suite.encrypt(password.encode())
    with open(os.path.join(script_dir, "pwd.list"), "wb") as f:
        f.write(encrypted_password)

def read_password_from_file():
    with open(os.path.join(script_dir, "pwd.list"), "rb") as f:
        encrypted_password = f.read()
    return cipher_suite.decrypt(encrypted_password).decode()

# --- GUI Functions ---

def copy_password_callback(password):
    # Copy the password to the clipboard
    window.clipboard_clear()
    window.clipboard_append(password)

def generate_password_callback(length, use_lowercase, use_uppercase, use_digits, use_symbols):
    try:
        password = generate_password(int(length), use_lowercase, use_uppercase, use_digits, use_symbols)
        password_label.config(text=password)
        save_encrypted_password(password)
    except ValueError as e:
        password_label.config(text=str(e))



#Adding name for the service what the password is for
service_label = tk.Label(window, text="Navn på tjenesten passordet tilhører:")
service_label.pack()

#entry for the service name
service_entry = tk.Entry(window)
service_entry.pack()

# Add a label for the password length
length_label = tk.Label(window, text="Passordlengde:")
length_label.pack()

# Add an entry for the password length
length_entry = tk.Entry(window)
length_entry.pack()

# Add checkboxes for character sets
use_lowercase_var = tk.BooleanVar()
use_lowercase_checkbox = tk.Checkbutton(window, text="Bruk små bokstaver", variable=use_lowercase_var)
use_lowercase_checkbox.pack()

use_uppercase_var = tk.BooleanVar()
use_uppercase_checkbox = tk.Checkbutton(window, text="Bruk store bokstaver", variable=use_uppercase_var)
use_uppercase_checkbox.pack()

use_digits_var = tk.BooleanVar()
use_digits_checkbox = tk.Checkbutton(window, text="Bruk tall", variable=use_digits_var)
use_digits_checkbox.pack()

use_symbols_var = tk.BooleanVar()
use_symbols_checkbox = tk.Checkbutton(window, text="Bruk symboler", variable=use_symbols_var)
use_symbols_checkbox.pack()

# Add a button to generate the password
generate_button = tk.Button(window, text="Generer passord", command=lambda: generate_password_callback(length_entry.get(), use_lowercase_var.get(), use_uppercase_var.get(), use_digits_var.get(), use_symbols_var.get()))
generate_button.pack()

# Add a label to display the generated password
password_label = tk.Label(window, text="")
password_label.pack()

# Add a button to copy the generated password to the clipboard
copy_button = tk.Button(window, text="Kopier passord", command=lambda: copy_password_callback(password_label.cget("text")))
copy_button.pack()

# Add a button to read the password from file
read_button = tk.Button(window, text="Les passord fra fil", command=lambda: password_label.config(text=read_password_from_file()))
read_button.pack()

# Start the main loop
window.mainloop()