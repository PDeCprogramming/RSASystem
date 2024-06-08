# RSASystem

This program allows you encrpyt and decrypt given messages with commands

## installations

This program is coded in raw python, so you don't need to install anything!

## Usage

To use the program, you can enter commands and encrypt and decrypt all you want! Using a sort of "game loop" like here:
```python

while True:
        command = input("Enter command: ").strip().lower()
        
        if command == 'help':
            print_help()
        
        elif command == 'encrypt':
            message = input("Enter a message to encrypt: ")
            encrypted_msg = encrypt(public, message)
            print(f"Encrypted message: {encrypted_msg}")
        
        elif command == 'decrypt':
            encrypted_msg = input("Enter the encrypted message (as a list of integers): ")
            try:
                encrypted_msg = eval(encrypted_msg)
                decrypted_msg = decrypt(private, encrypted_msg)
                print(f"Decrypted message: {decrypted_msg}")
            except Exception as e:
                print(f"Error in decrypting message: {e}")
        
        elif command == 'setbits':
            try:
                bits = int(input("Enter the number of bits for prime generation: "))
                public, private, p, q, n, phi, e, d = generate_keypair(bits)
                start_time = time.time()
                print(f"Keypair generated with {bits} bits.")
            except ValueError:
                print("Invalid input. Please enter a valid number of bits.")
        
        elif command == 'showkeys':
            print(f"Public key: {public}")
            print(f"Private key: {private}")
        
        elif command == 'savemessage':
            encrypted_msg = input("Enter the encrypted message (as a list of integers) to save: ")
            try:
                encrypted_msg = eval(encrypted_msg)
                filename = input("Enter the filename to save the message: ")
                save_to_file(filename, encrypted_msg)
            except Exception as e:
                print(f"Error in saving message: {e}")
        
        elif command == 'loadmessage':
            filename = input("Enter the filename to load the message from: ")
            encrypted_msg = load_from_file(filename)
            if encrypted_msg:
                try:
                    decrypted_msg = decrypt(private, encrypted_msg)
                    print(f"Decrypted message: {decrypted_msg}")
                except Exception as e:
                    print(f"Error in decrypting message: {e}")
        
        elif command == 'showconfig':
            print(f"Current bit length: {bits}")
            print(f"Prime p: {p}")
            print(f"Prime q: {q}")
            print(f"Modulus n: {n}")
            print(f"Euler's Totient (phi): {phi}")
            print(f"Encryption exponent e: {e}")
            print(f"Decryption exponent d: {d}")
            print(f"Key generation time: {time.time() - start_time:.2f} seconds")
        
        elif command == 'resetkeys':
            public, private, p, q, n, phi, e, d = generate_keypair(bits)
            start_time = time.time()
            print(f"Keypair regenerated with {bits} bits.")
        
        elif command == 'exit':
            print("Exiting...")
            break
```
you can enter as many messages you want, and has a variety of commands for you to use! A list of such could include:
```txt
  help         - Show this help message
  encrypt      - Encrypt a message
  decrypt      - Decrypt a message
  setbits      - Set the number of bits for prime generation
  showkeys     - Show the current public and private keys
  savemessage  - Save an encrypted message to a file
  loadmessage  - Load an encrypted message from a file
  showconfig   - Show the current configuration
  resetkeys    - Regenerate keys with the current bit length
  exit         - Exit the program
```

So, for example, I could enter the command "encrypt" and then it will tell me what to enter, say "Hello, world!" the program would return the encrypted message, as a python container. Then, you could even decrypt the message, by typing "decrypt" as a command and copy and paste the encrypted message in, to get your message back! 
Like so:

```txt
Enter command: encrypt
Enter a message to encrypt: Hello, world!
Encrypted message: [8036541825965420025, 253672535049798945, 3456546676198118188, 3456546676198118188, 6674608831075319900, 3885808004865636619, 9813581443727555719, 11098344367305747824, 6674608831075319900, 109237599331922911, 3456546676198118188, 12051426298979532245, 11006295562850898074]
Enter command: decrypt
Enter the encrypted message (as a list of integers): [8036541825965420025, 253672535049798945, 3456546676198118188, 3456546676198118188, 6674608831075319900, 3885808004865636619, 9813581443727555719, 11098344367305747824, 6674608831075319900, 109237599331922911, 3456546676198118188, 12051426298979532245, 11006295562850898074]
Decrypted message: Hello, world!
```
