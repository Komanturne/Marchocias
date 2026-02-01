# Marchocias
*This has not yet been tested in any form of cryptography, and therefore should be used with skepticism, this probably isn't a good idea for use on large-scale projects, or anything that would require any form of 'real' encryption.*

This is an encryption algorithm that is written in *Python* and uses the Skipjack F-table, while improving on the original algorithm by using a **384 bit** key-size, and **64** rounds. This also uses some elements of certain *Lai-Massay Algorithms* in order to avoid the pitfalls of Feistal algorithms, specifically by adding more operations *(and obviously using them)* than Feistal algorithms usually use, though this still uses the majority of the Feistal algorithms blueprints. This algorithm also includes the *Tiny Encryption Algorithm* as padding in the beginning and the end in order to prevent certain baggage, though this is not necessarily a security measure meant to prevent decryption, but to increase breaking-time. This is made as a passion project, and the code-base is admitably kinda scuffed, but I believe that it's still acceptable and doesn't get in the way of performance or readability.

## Instructions & Example
In order to use the program, you will need to:
1. Copy the Github Repo, either through *"git clone"* or you can copy the file *"marchocias.py"*
2. Next, create another python file, in the same folder, and include the file using
`from marchocias import Marchocias`

For an example, here is an example that I coded that generates a key, and has a basic encryption & decryption in the terminal

```
import os

from marchocias import Marchocias
KEY_FILE = "keys/mykey.bin"
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    else:
        key = os.urandom(48)
        os.makedirs("keys", exist_ok=True)
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        print("New key generated.")
        return key
def main():
    key = load_or_create_key()
    cipher = Marchocias(key)
    while True:
        print("\n1 - Encrypt Message")
        print("2 - Decrypt Message")
        print("3 - Exit")
        choice = input(">> ").strip()
        if choice == "1":
            msg = input("Message: ").encode()
            ct = cipher.encrypt(msg)
            print("\nCiphertext (hex):")
            print(ct.hex())
        elif choice == "2":
            hexdata = input("Ciphertext (hex): ").strip()
            try:
                ct = bytes.fromhex(hexdata)
                pt = cipher.decrypt(ct)
                print("\nPlaintext:")
                print(pt.decode())
            except Exception as e:
                print("Error:", e)
        elif choice == "3":
            break
        else:
            print("Invalid choice.")
if __name__ == "__main__":
    main()
```

Thank you for using this algorithm, and supporting this passion project.
