from datetime import timedelta
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, PhotoImage
from tkinter.font import Font
import argparse
import os
import sys
import webbrowser
from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from getpass import getpass
import warnings

# version number
version = "1.0.0"

# Suppress all warnings
warnings.simplefilter('ignore')


# Function to get the path of a resource
def resource_path(relative_path):
    """ Get the absolute path to the resource """
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # The application is running in a bundle (compiled with Nuitka)
        base_path = sys._MEIPASS
    else:
        # The application is running in a normal Python environment
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)

def is_cli_mode():
    return len(sys.argv) > 1



# Define functions for key generation, encryption, and decryption
def generate_keys(passphrase, private_key_file, public_key_file, overwrite=False, expire_date=None, uid=None, key_size=4096):
    
    # Generate primary key (RSA default)
    primary_key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, key_size)
    #uid = PGPUID.new(uid)
    
    # Calculate the expiration date as a timezone-naive datetime object
    #expires = datetime.utcnow() + expire_date if expire_date is not None else None


    primary_key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                        hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
                        ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.Camellia256],
                        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
                        key_expiration=expire_date)  # Set the expiration date here

    # Generate subkey for encryption
    subkey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    primary_key.add_subkey(subkey, usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})

    # Protect the primary key with the passphrase
    primary_key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)


    # Save private key to a file
    if not overwrite and os.path.exists(private_key_file):
        print(f"Error: {private_key_file} already exists. Use --overwrite to force overwrite.")
        return False
    with open(private_key_file, 'w') as f:
        f.write(str(primary_key))
    print(f"Private key saved to {private_key_file}")

    # Save public key to a file
    if not overwrite and os.path.exists(public_key_file):
        print(f"Error: {public_key_file} already exists. Use --overwrite to force overwrite.")
        return False
    with open(public_key_file, 'w') as f:
        f.write(str(primary_key.pubkey))
    print(f"Public key saved to {public_key_file}")
    return True


def encrypt_data(data, public_key_file, output_filename=None):
    
    if output_filename is None:
        output_filename = f"{public_key_file}.pgp"

    # Load the public key
    with open(public_key_file, 'r') as f:
        public_key = PGPKey()
        public_key.parse(f.read())

    # Create a PGPMessage from the binary data
    message = PGPMessage.new(data)

    # Encrypt the message with the public key
    encrypted_message = public_key.encrypt(message)

    # Write the encrypted message to the file
    with open(output_filename, 'wb') as f:
        f.write(bytes(encrypted_message))
    print(f"Encrypted data saved to {output_filename}")
    return True


def decrypt_file(file_path, private_key_file, passphrase, output_filename=None):
    # Load private key from file
    with open(private_key_file, 'r') as f:
        private_key = PGPKey()
        private_key.parse(f.read())

    # Load encrypted message from file
    with open(file_path, 'rb') as file:  # Open in binary mode
        encrypted_message = PGPMessage.from_blob(file.read())

    # Unlock the private key with the passphrase
    with private_key.unlock(passphrase):
        if not private_key.is_unlocked:
            raise ValueError("The private key could not be unlocked. Check your passphrase.")
        # Decrypt the message
        decrypted_message = private_key.decrypt(encrypted_message)

    # Determine the output filename if not provided
    if output_filename is None:
        output_filename = file_path.rsplit('.pgp', 1)[0] if file_path.endswith('.pgp') else file_path + '.decrypted'

    # Write the decrypted message to the file
    with open(output_filename, 'wb') as f:  # Open in binary mode
        f.write(bytes(decrypted_message.message))  # Write as bytes
    print(f"Decrypted data saved to {output_filename}")
    return True


# Define GUI functions
def generate_keys_gui():

    if getattr(sys, 'frozen', False):
        script_dir = os.path.dirname(sys.executable)
    else:
        script_dir = os.path.dirname(os.path.realpath(__file__))
    
    def validate_number(P):
        if P.isdigit() or P == "" or P == "0 = No Expire":
            return True
        else:
            return False

    def on_entry_click(event):
        """Function to be called when entry is clicked."""
        if expire_years_entry.get() == '0 = No Expire':
            expire_years_entry.delete(0, "end")  # delete all the text in the entry
            expire_years_entry.insert(0, '')  # Insert blank for user input
            expire_years_entry.config(fg='black')

    def on_focusout(event):
        """Function to be called when entry loses focus."""
        if expire_years_entry.get() == '':
            expire_years_entry.insert(0, '0 = No Expire')
            expire_years_entry.config(fg='grey')
    
    # Dialog window with fields for name, email, expiration years, and passphrase
    dialog = tk.Toplevel()
    dialog.title("Key Generation")
    dialog.resizable(False, False)
    
	# Register the validation command
    vcmd = (dialog.register(validate_number), '%P')
    
    tk.Label(dialog, text="Name:").grid(row=0, column=0, sticky="e")
    name_entry = tk.Entry(dialog)
    name_entry.grid(row=0, column=1)
    
    tk.Label(dialog, text="Email:").grid(row=1, column=0, sticky="e")
    email_entry = tk.Entry(dialog)
    email_entry.grid(row=1, column=1)
    
    tk.Label(dialog, text="Expiration (years):").grid(row=2, column=0, sticky="e")
    expire_years_entry = tk.Entry(dialog, validate='key', validatecommand=vcmd, fg='grey')
    expire_years_entry.insert(0, '0 = No Expire')
    expire_years_entry.bind('<FocusIn>', on_entry_click)
    expire_years_entry.bind('<FocusOut>', on_focusout)
    expire_years_entry.grid(row=2, column=1)
    

    tk.Label(dialog, text="Key Size (bits):").grid(row=3, column=0, sticky="e")
    key_size_var = tk.StringVar(value='4096')  # Set default value
    key_size_options = ['1024', '2048', '4096', '8192']
    key_size_dropdown = tk.OptionMenu(dialog, key_size_var, *key_size_options)
    key_size_dropdown.grid(row=3, column=1)


    tk.Label(dialog, text="Passphrase:").grid(row=4, column=0, sticky="e")
    passphrase_entry = tk.Entry(dialog, show='*')
    passphrase_entry.grid(row=4, column=1)
    
    tk.Label(dialog, text="Verify Passphrase:").grid(row=5, column=0, sticky="e")
    confirm_passphrase_entry = tk.Entry(dialog, show='*')
    confirm_passphrase_entry.grid(row=5, column=1)
    
    def on_ok():
        name = name_entry.get()
        email = email_entry.get()
        expire_years = expire_years_entry.get()
        key_size = int(key_size_var.get())
        passphrase = passphrase_entry.get()
        confirm_passphrase = confirm_passphrase_entry.get()

        if passphrase != confirm_passphrase:
            messagebox.showerror("Error", "Passphrases do not match.")
            return
        
        if not name or not email or not passphrase:
            messagebox.showerror("Error", "Name, email, and passphrase are required.")
            return
        
        try:
            expire_years = int(expire_years) if expire_years else 0
            expire_date = timedelta(days=expire_years * 365) if expire_years else None
        except ValueError:
            messagebox.showerror("Error", "Invalid number of years.")
            return
        
        private_key_file = filedialog.asksaveasfilename(initialdir=script_dir, defaultextension=".asc", filetypes=[("PGP keys", "*.asc")],
                                                        title="Save Private Key As")
        if not private_key_file:
            return
        
        public_key_file = filedialog.asksaveasfilename(initialdir=script_dir, defaultextension=".asc", filetypes=[("PGP keys", "*.asc")],
                                                       title="Save Public Key As")
        if not public_key_file:
            return
        
        try:
            uid = PGPUID.new(f'{name} <{email}>')
            generate_keys(passphrase, private_key_file, public_key_file, overwrite=True, expire_date=expire_date, uid=uid, key_size=key_size)

            messagebox.showinfo("Success", "Keys generated successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
        
        dialog.destroy()
    
    # OK button with increased width and centered at the bottom
    ok_button = tk.Button(dialog, text="OK", command=on_ok, width=10)  # Adjust width as needed
    ok_button.grid(row=6, column=0, columnspan=2, pady=10)  # Adjust row index as needed
    ok_button.grid_configure(sticky="ew")  # Make the button expand to fill the cell horizontally
    
    # Center the dialog on the parent window
    dialog.update_idletasks()  # Update internal states
    dialog_width = dialog.winfo_width()
    dialog_height = dialog.winfo_height()
    parent_x = root.winfo_x()
    parent_y = root.winfo_y()
    parent_width = root.winfo_width()
    parent_height = root.winfo_height()
    dialog_x = parent_x + (parent_width - dialog_width) // 2
    dialog_y = parent_y + (parent_height - dialog_height) // 2
    dialog.geometry(f"+{dialog_x}+{dialog_y}")

    dialog.transient(root)  # Set to be on top of the main window
    dialog.grab_set()  # Modal
    root.wait_window(dialog)  # Wait for the dialog to be closed


def encrypt_file_gui():

    if getattr(sys, 'frozen', False):
        script_dir = os.path.dirname(sys.executable)
    else:
        script_dir = os.path.dirname(os.path.realpath(__file__))

    public_key_file = filedialog.askopenfilename(initialdir=script_dir, filetypes=[("PGP keys", "*.asc")], title="Select Public Key")
    
    public_key_file = r"{}".format(public_key_file)  # Convert to raw string
    if not public_key_file:
        #messagebox.showerror("Error", "No public key file selected.")
        return

    data_file = filedialog.askopenfilename(initialdir=script_dir, title="Select a File to Encrypt")
    data_file = r"{}".format(data_file)  # Convert to raw string
    if not data_file:
        messagebox.showerror("Error", "No file selected for encryption.")
        return

    try:
        with open(data_file, 'rb') as file:  # Open in binary mode
            data_to_encrypt = file.read()

        # Suggest an output filename by appending .pgp to the original filename
        suggested_output_filename = os.path.basename(data_file) + '.pgp'

        output_filename = filedialog.asksaveasfilename(initialdir=script_dir, initialfile=suggested_output_filename, defaultextension=".pgp", filetypes=[("PGP files", "*.pgp")],
                                                   title="Save Encrypted File As")
        
        #output_filename = r"{}".format(output_filename)  # Convert to raw string
        if not output_filename:  # User cancelled the operation
            return

        encrypt_data(data_to_encrypt, public_key_file, output_filename)
        messagebox.showinfo("Success", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))




def encrypt_file_cli(args):
    input_filename = args.file
    public_key_file = args.public_key_file
    output_filename = args.output if args.output else f"{input_filename}.pgp"

    # Check if the output file already exists
    if os.path.exists(output_filename) and not args.overwrite:
        print(f"Error: The file '{output_filename}' already exists. Use --overwrite to force overwrite.")
        return False

    with open(input_filename, 'rb') as file:  # Open in binary mode
        data_to_encrypt = file.read()
    encrypt_data(data_to_encrypt, public_key_file, output_filename)
    print(f"File encrypted successfully: {output_filename}")
    return True

def decrypt_file_gui():
    if getattr(sys, 'frozen', False):
        script_dir = os.path.dirname(sys.executable)
    else:
        script_dir = os.path.dirname(os.path.realpath(__file__))

    private_key_file = filedialog.askopenfilename(initialdir=script_dir, filetypes=[("PGP keys", "*.asc")], title="Select Private Key")
    
    if not private_key_file:
        return

    passphrase = simpledialog.askstring("Passphrase", "Enter the private key passphrase:", show='*')
    if passphrase is None:
        return

    encrypted_file_path = filedialog.askopenfilename(initialdir=script_dir, filetypes=[("PGP files", "*.pgp")], title="Select Encrypted File")
    if not encrypted_file_path:
        return

    # Extract the filename from the full path and suggest it as the default output filename
    default_output_filename = os.path.basename(encrypted_file_path.rsplit('.pgp', 1)[0]) if encrypted_file_path.endswith('.pgp') else os.path.basename(encrypted_file_path)

    output_filename = filedialog.asksaveasfilename(initialdir=script_dir, initialfile=default_output_filename, title="Save Decrypted File As")
    if not output_filename:
        return

    try:
        decrypt_file(encrypted_file_path, private_key_file, passphrase, output_filename)
        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Define CLI functions
def generate_keys_cli(args):
    passphrase = args.passphrase or getpass("Enter passphrase for the private key: ")
    expire_date = timedelta(days=args.expire_years * 365) if args.expire_years else None
    uid = PGPUID.new(f'{args.name} <{args.email}>')
    generate_keys(passphrase, args.private_key_file, args.public_key_file, args.overwrite, expire_date=expire_date, uid=uid, key_size=args.key_size)


def show_about():
    messagebox.showinfo("About", f"PGP FileLock\nVersion {version}\n 2024 Lobito")

def open_github():
    webbrowser.open_new_tab("https://github.com/x011/PGP-FileLock")

def decrypt_file_cli(args):
    encrypted_file_path = args.file
    private_key_file = args.private_key_file
    passphrase = args.passphrase or args.passphrase or getpass("Enter passphrase for the private key: ")
    output_filename = args.output if args.output else f"{encrypted_file_path.rsplit('.pgp', 1)[0]}"

    # Check if the output file already exists
    if os.path.exists(output_filename) and not args.overwrite:
        print(f"Error: The file '{output_filename}' already exists. Use --overwrite to force overwrite.")
        return False

    decrypt_file(encrypted_file_path, private_key_file, passphrase, output_filename)
    print(f"File decrypted successfully: {output_filename}")
    return True


parser = argparse.ArgumentParser(description="PGP FileLock")
subparsers = parser.add_subparsers(help='commands', dest='command')

# Subparser for key generation
generate_parser = subparsers.add_parser('generate', help='Generate PGP keys')
generate_parser.add_argument('--name', required=True, help='Name for the UID')
generate_parser.add_argument('--email', required=True, help='Email for the UID')
generate_parser.add_argument('--expire-years', type=int, default=0, help='Number of years until the key expires (optional, default: 0 for no expiration)')

generate_parser.add_argument('--key-size', type=int, choices=[1024, 2048, 4096, 8192], default=4096, help='Key size in bits (default: 4096)')



generate_parser.add_argument('--passphrase', nargs='?', default=None, help='Passphrase for the private key (will prompt if not provided)')

generate_parser.add_argument('--private-key-file', nargs='?', default='private_key.asc', help='Filename for the private key (default: private_key.asc in current directory)')
generate_parser.add_argument('--public-key-file', nargs='?', default='public_key.asc', help='Filename for the public key (default: public_key.asc in current directory)')
generate_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing keys without prompt (default: False)')

# Subparser for encryption
encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
encrypt_parser.add_argument('--file', required=True, help='File to encrypt')
encrypt_parser.add_argument('--public-key-file', required=True, help='Public key file for encryption')
encrypt_parser.add_argument('--output', help='Output filename for the encrypted file')
encrypt_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing encrypted file without prompt')

# Subparser for decryption
decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
decrypt_parser.add_argument('--file', required=True, help='Encrypted file to decrypt')
decrypt_parser.add_argument('--private-key-file', required=True, help='Private key file for decryption')
decrypt_parser.add_argument('--passphrase', help='Passphrase for the private key')
decrypt_parser.add_argument('--output', help='Output filename for the decrypted file')
decrypt_parser.add_argument('--overwrite', action='store_true', help='Overwrite existing decrypted file without prompt')

if __name__ == "__main__":
    if is_cli_mode():
        # Command-line arguments are present, run in CLI mode
        args = parser.parse_args()
        if args.command == 'generate':
            generate_keys_cli(args)
        elif args.command == 'encrypt':
            encrypt_file_cli(args)
        elif args.command == 'decrypt':
            decrypt_file_cli(args)
    else:
        # No command-line arguments, run in GUI mode
        if os.name == 'nt':  # Only for Windows
            import ctypes
            # Get a handle to the console window and hide it
            kernel32 = ctypes.WinDLL('kernel32')
            console_window = kernel32.GetConsoleWindow()
            if console_window != 0:
                user32 = ctypes.WinDLL('user32')
                user32.ShowWindow(console_window, 0)  # SW_HIDE = 0

        # GUI mode
        root = tk.Tk()
        root.title("PGP FileLock")

        # Center the window on the screen
        window_width = root.winfo_reqwidth()
        window_height = root.winfo_reqheight()
        position_right = int(root.winfo_screenwidth() / 2 - window_width / 2)
        position_down = int(root.winfo_screenheight() / 2 - window_height / 2)
        root.geometry(f"+{position_right}+{position_down}")

        # Make the window not resizable
        root.resizable(False, False)

        # Create a menu bar
        menu_bar = tk.Menu(root)

        # Create a "Help" menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="GitHub Project", command=open_github)
        help_menu.add_command(label="About", command=show_about)

        menu_bar.add_cascade(label="Help", menu=help_menu)

        # Set the menu bar to the window
        root.config(menu=menu_bar)

        # Define a larger font
        large_font = Font(family="Helvetica", size=14, weight="bold")

        frame = tk.Frame(root)
        frame.pack(padx=10, pady=(10, 20))  # pady=(top, bottom)

        # Load images and subsample them to the desired size
        original_generate_image = PhotoImage(file=resource_path("key.png"))
        generate_image = original_generate_image.subsample(2, 2)  # Replace 2, 2 with the appropriate subsample factors

        original_encrypt_image = PhotoImage(file=resource_path("lock.png"))
        encrypt_image = original_encrypt_image.subsample(2, 2)  # Replace 2, 2 with the appropriate subsample factors

        original_decrypt_image = PhotoImage(file=resource_path("unlock.png"))
        decrypt_image = original_decrypt_image.subsample(2, 2)  # Replace 2, 2 with the appropriate subsample factors

        # Create buttons with text and scaled images
        generate_button = tk.Button(frame, text="Generate Keys\n", image=generate_image, compound='bottom', command=generate_keys_gui, font=large_font)
        generate_button.pack(side=tk.LEFT, padx=5)

        encrypt_button = tk.Button(frame, text="Encrypt File\n", image=encrypt_image, compound='bottom', command=encrypt_file_gui, font=large_font)
        encrypt_button.pack(side=tk.LEFT, padx=5)

        decrypt_button = tk.Button(frame, text="Decrypt File\n", image=decrypt_image, compound='bottom', command=decrypt_file_gui, font=large_font)
        decrypt_button.pack(side=tk.LEFT, padx=5)

        # Keep a reference to the images
        generate_button.image = generate_image
        encrypt_button.image = encrypt_image
        decrypt_button.image = decrypt_image

        root.mainloop()