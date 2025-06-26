from pathlib import Path
from os import urandom
from typing import Optional, NoReturn
from sys import exit, stderr, argv
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ENCRYPTED_FILE = "enc"
SALT_FILE = "salt"
DEST_FILE = "OUT.md"

EXIT_SUCCESS = 0
EXIT_ERR_FILE_NOT_FOUND = 1
EXIT_ERR_BAD_OPTIONS = 2
EXIT_ERR_ENCRYPTION = 3
EXIT_ERR_DECRYPTION = 4
EXIT_ERR_FILE_EXISTS = 5

def prompt_yn(s: str) -> bool:
    while True:
        m = input(s).strip().lower()
        if m in ["yes", "y"]:
            return True
        elif m in ["n", "no"]:
            return False
    
def clean(s: str) -> str:
    return s.lower().strip()

def read_file(file: str) -> Optional[bytes]:
    try:
        with open(file, "rb") as f:
            return f.read(-1)
    except:
        return None

def write_to_file(file: str, contents: bytes) -> None:
    with open(file, "wb") as f:
        f.write(contents)

def EXIT(msg: str, status_code: int) -> NoReturn:
    print(msg, file=stderr)
    exit(status_code)

def encrypt(token: bytes, password: bytes, salt: bytes) -> Optional[bytes]:
    try:
        return __create_fernet(salt, password).encrypt(token)
    except:
        return None

def decrypt(token: bytes, password: bytes, salt: bytes) -> Optional[bytes]:
    try:
        return __create_fernet(salt, password).decrypt(token)
    except:
        return None

def __create_fernet(salt: bytes, password: bytes) -> Fernet:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1_200_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)

def prompt_for_password() -> bytes:
    print("Answers are case insensitive")
    mid_movie = clean(input("A mid movie: "))
    hand_man = clean(input("Stage name of an artist with cool hands: "))
    your_birthday = clean(input("Your birthday in MM/DD/YYYY format (Example: 01/01/2001): "))
    password = (mid_movie + hand_man + your_birthday).encode()
    return password
    

if __name__ == '__main__':

    opt_encrypt = False
    opt_encrypt_file = None

    argv = argv[1:]
    while argv:
        arg = argv[0]
        if arg in ["-e", "encrypt", "-encrypt", "--encrypt"]:
            opt_encrypt = True
            argv = argv[1:]
            if not argv:
                EXIT("Encrypt option requires filename to encrypt", EXIT_ERR_BAD_OPTIONS)
            if not Path(argv[0]).is_file():
                EXIT("File to encrypt does not exist", EXIT_ERR_FILE_NOT_FOUND)
            opt_encrypt_file = argv[0]
        argv = argv[1:]

    if opt_encrypt:
        token = read_file(opt_encrypt_file) # type: ignore
        if token is None:
            EXIT(f"Could not read {opt_encrypt_file}", EXIT_ERR_FILE_NOT_FOUND)
        salt = urandom(16)
        
        password = prompt_for_password()
        encrypted_text = encrypt(token, password, salt)

        if encrypted_text is None:
            EXIT("Could not encrypt???", EXIT_ERR_ENCRYPTION)
        
        if Path(ENCRYPTED_FILE).exists():
            if not prompt_yn(f"'{ENCRYPTED_FILE}' exists. Overwrite? "):
                EXIT("Exiting...", EXIT_ERR_FILE_EXISTS)
        if Path(SALT_FILE).exists():
            if not prompt_yn(f"'{SALT_FILE}' exists. Overwrite? "):
                EXIT("Exiting...", EXIT_ERR_FILE_EXISTS)

        write_to_file(ENCRYPTED_FILE, encrypted_text)
        write_to_file(SALT_FILE, salt)
        print(f"Done. Wrote to {ENCRYPTED_FILE} and {SALT_FILE}")
        
    else:
        token = read_file(ENCRYPTED_FILE)
        if token is None:
            EXIT(f"Could not read {ENCRYPTED_FILE}", EXIT_ERR_FILE_NOT_FOUND)
        salt = read_file(SALT_FILE)
        if salt is None:
            EXIT(f"Could not read {SALT_FILE}", EXIT_ERR_FILE_NOT_FOUND)

        password = prompt_for_password()
        decrypted_text = decrypt(token, password, salt)

        if decrypted_text is None:
            EXIT("Incorrect password", EXIT_ERR_DECRYPTION)
        else:
            write_to_file(DEST_FILE, decrypted_text)
            print(f"Decrypted into {DEST_FILE}")
