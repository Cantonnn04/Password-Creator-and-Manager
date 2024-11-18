import tkinter as tk
from tkinter import simpledialog, messagebox
import random
import string
import os
import stat
import sys

# Determine the base path for data storage
if getattr(sys, 'frozen', False):
    # If the application is running as a bundled executable
    base_path = os.path.dirname(sys.executable)
else:
    # If running as a script
    base_path = os.path.dirname(os.path.abspath(__file__))

# Create a folder named "data" in the same directory as the executable or script
appdata_path = os.path.join(base_path, "data")
os.makedirs(appdata_path, exist_ok=True)  # Create the directory if it doesn't exist

# Function to get file paths
def get_file_path(filename):
    return os.path.join(appdata_path, filename)

# Function to set file permissions to be accessible only by the owner
def set_file_permissions(filepath):
    os.chmod(filepath, stat.S_IRUSR | stat.S_IWUSR)  # Read and write permissions for the owner only

# Create the main application window
m = tk.Tk()
m.configure(bg="#555555")
m.geometry("475x400")  # Increase width to allow more space for padding
m.resizable(False, False)
m.title('Password Tool')

# Create a main frame to center-align with padding
main_frame = tk.Frame(m, padx=20, pady=10)  # Adjust padx for side padding
main_frame.pack(expand=False)
main_frame.configure(bg="#555555")

# Function to validate input for password length
def NumOnly(new_value):
    return new_value == "" or new_value.isdigit()

validate = (m.register(NumOnly), '%P')

# Global variable for storing plaintext password
user_password = None

# Function to set the user's password on first launch
def set_user_password():
    global user_password
    user_password = simpledialog.askstring("Set Password", "Please set a password for your notes:", show="*")
    if user_password:
        password_file_path = get_file_path("user_password.txt")
        with open(password_file_path, "w") as file:
            file.write(user_password)
        set_file_permissions(password_file_path)  # Set file permissions
        load_textbox_contents()  # Load notes after setting password
    else:
        messagebox.showwarning("Warning", "Password cannot be empty.")

# Function to load user password from file
def load_user_password():
    global user_password
    password_file_path = get_file_path("user_password.txt")
    if os.path.exists(password_file_path):
        with open(password_file_path, "r") as file:
            user_password = file.read().strip()
    else:
        set_user_password()

# Function to verify the user's password
def verify_password():
    entered_password = simpledialog.askstring("Enter Password", "Please enter your password:", show="*")
    return entered_password == user_password

# Function to generate passwords
def generate_passwords():
    length_value = length.get()
    try:
        length_value = int(length_value)
    except ValueError:
        return
    
    if length_value > 25:
        length_value = 25

    # Get selected options
    use_numbers = Numbers.var.get()
    use_capitals = Capitals.var.get()
    use_special = SpecialChar.var.get()

    character_pool = string.ascii_lowercase

    if use_numbers:
        character_pool += string.digits
    if use_capitals:
        character_pool += string.ascii_uppercase
    if use_special:
        character_pool += string.punctuation

    # Generate passwords
    passwords = []
    for _ in range(5):
        password = ''.join(random.choice(character_pool) for _ in range(length_value))
        passwords.append(password)

    # Clear previous passwords
    for widget in password_frame.winfo_children():
        widget.destroy()
    
    # Display new passwords
    for i, password in enumerate(passwords):
        password_label = tk.Label(password_frame, text=password)
        password_label.grid(row=i, column=0, padx=5, pady=2, sticky="w")
        
        copy_button = tk.Button(password_frame, text="Copy", command=lambda p=password: copy_to_clipboard(p))
        copy_button.grid(row=i, column=1, padx=5, pady=2)

# Function to copy a password to the clipboard
def copy_to_clipboard(password):
    m.clipboard_clear()
    m.clipboard_append(password) 
    m.update() 

# Function to save contents of the textbox to a plaintext file
def save_textbox_contents():
    if verify_password():
        notes_file_path = get_file_path("user_notes.txt")
        with open(notes_file_path, "w") as file:
            file.write(textbox.get("1.0", tk.END).strip())
        set_file_permissions(notes_file_path)  # Set file permissions
        messagebox.showinfo("Success", "Notes saved successfully.")
    else:
        messagebox.showerror("Error", "Incorrect password.")

# Function to load saved contents into the textbox at startup
def load_textbox_contents():
    notes_file_path = get_file_path("user_notes.txt")
    if os.path.exists(notes_file_path):
        with open(notes_file_path, "r") as file:
            content = file.read()
            textbox.insert("1.0", content)

# Function to see notes
def see_notes():
    if verify_password():
        textbox.delete("1.0", tk.END)
        load_textbox_contents()  # Load notes if password is correct
    else:
        messagebox.showerror("Error", "Incorrect password.")

# Function to reset notes and password
def reset_notes_and_password():
    global user_password
    confirm = messagebox.askyesno("Confirm Reset", "Are you sure you want to reset your notes and password?")
    if confirm:
        notes_file_path = get_file_path("user_notes.txt")
        password_file_path = get_file_path("user_password.txt")
        os.remove(notes_file_path) if os.path.exists(notes_file_path) else None
        os.remove(password_file_path) if os.path.exists(password_file_path) else None
        user_password = None
        set_user_password()  # Prompt to set a new password

# Load user password on startup
load_user_password()

# GUI elements
w = tk.Label(main_frame, text='Password Generator', fg="white")
w.configure(bg="#555555")
w.grid(row=0, column=0, columnspan=2, pady=10)

l = tk.Label(main_frame, text='Notes', fg="white")
l.configure(bg="#555555")
l.grid(row=0, column=2, sticky='n', pady=10)

# Checkbuttons for options
Numbers = tk.Checkbutton(main_frame, text='Numbers')
Numbers.var = tk.BooleanVar()  
Numbers.config(variable=Numbers.var)
Numbers.grid(row=1, column=0, sticky="w")

Capitals = tk.Checkbutton(main_frame, text='Capital Letters')
Capitals.var = tk.BooleanVar()
Capitals.config(variable=Capitals.var)
Capitals.grid(row=2, column=0, sticky="w")

SpecialChar = tk.Checkbutton(main_frame, text='Special Characters')
SpecialChar.var = tk.BooleanVar()
SpecialChar.config(variable=SpecialChar.var)
SpecialChar.grid(row=3, column=0, sticky="w")

# Entry for password length
LengthLabel = tk.Label(main_frame, text='Password Length (Max 25)')
LengthLabel.grid(row=4, column=0, sticky="w")

length = tk.Entry(main_frame, validate='key', validatecommand=validate, width=10)
length.grid(row=4, column=1, padx=5)

# Generate button
button = tk.Button(main_frame, text='Generate', width=30, command=generate_passwords)
button.grid(row=5, column=0, columnspan=2, padx=5, pady=3)

# Frame to display generated passwords below the "Generate" button
password_frame = tk.Frame(main_frame)
password_frame.configure(bg="#52555a")
password_frame.grid(row=6, column=0, columnspan=2, pady=10, sticky="w")

# Textbox for notes or to view generated passwords
textbox = tk.Text(main_frame, height=10, width=20)
textbox.grid(row=1, column=2, rowspan=5, padx=10, pady=5, sticky="n")

# Frame for buttons below the textbox to keep them in one place
button_frame = tk.Frame(main_frame)
button_frame.configure(bg="#555555")
button_frame.grid(row=6, column=2, sticky="n")

# Save button to save textbox contents
save_button = tk.Button(button_frame, text="Save", command=save_textbox_contents)
save_button.pack(pady=5)

# See notes button
see_button = tk.Button(button_frame, text="See Notes", command=see_notes)
see_button.pack(pady=5)

# Reset button for notes and password
reset_button = tk.Button(button_frame, text="Reset Notes/Password", command=reset_notes_and_password)
reset_button.pack(pady=5)

# Run the application
m.mainloop()
