from cryptography.fernet import Fernet
import os

# Generate a key (In a real app, you'd save this securely)
# For this project, we generate a temporary key for the session
key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt_file(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        
        encrypted_data = cipher.encrypt(data)
        
        new_path = file_path + ".locked"
        with open(new_path, "wb") as f:
            f.write(encrypted_data)
            
        os.remove(file_path) # Delete original
        return True, f"File Locked: {new_path}"
    except Exception as e:
        return False, str(e)

def decrypt_file(file_path):
    try:
        if not file_path.endswith(".locked"):
            return False, "Not a locked file!"

        with open(file_path, "rb") as f:
            data = f.read()
            
        decrypted_data = cipher.decrypt(data)
        
        # Remove .locked extension
        original_path = file_path.replace(".locked", "")
        with open(original_path, "wb") as f:
            f.write(decrypted_data)
            
        os.remove(file_path) # Delete locked file
        return True, f"File Unlocked: {original_path}"
    except Exception as e:
        return False, "Decryption Failed (Wrong Key or Corrupt File)"