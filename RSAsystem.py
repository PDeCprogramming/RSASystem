import random
import json
import time

def is_prime(num):
    """Check if a number is prime."""
    if num <= 1:
        return False
    if num <= 3:
        return True
    if num % 2 == 0 or num % 3 == 0:
        return False
    i = 5
    while i * i <= num:
        if num % i == 0 or num % (i + 2) == 0:
            return False
        i += 6
    return True

def generate_prime_candidate(length):
    """Generate an odd integer randomly."""
    p = random.getrandbits(length)
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length=1024):
    """Generate a prime number."""
    p = 4
    while not is_prime(p):
        p = generate_prime_candidate(length)
    return p

def gcd(a, b):
    """Compute the greatest common divisor."""
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    """Compute the modular inverse of a modulo m."""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

def generate_keypair(bits):
    """Generate RSA keypair."""
    p = generate_prime_number(bits // 2)
    q = generate_prime_number(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)
    
    d = modinv(e, phi)
    
    # Print bit length of the primes
    print(f"Bit length of prime p: {p.bit_length()}")
    print(f"Bit length of prime q: {q.bit_length()}")
    
    return ((e, n), (d, n), p, q, n, phi, e, d)

def encrypt(pk, plaintext):
    """Encrypt plaintext using a public key."""
    key, n = pk
    cipher = [pow(ord(char), key, n) for char in plaintext]
    return cipher

def decrypt(pk, ciphertext):
    """Decrypt ciphertext using a private key."""
    key, n = pk
    plain = [chr(pow(char, key, n)) for char in ciphertext]
    return ''.join(plain)

def save_to_file(filename, data):
    """Save data to a file."""
    with open(filename, 'w') as file:
        json.dump(data, file)
    print(f"Data saved to {filename}")

def load_from_file(filename):
    """Load data from a file."""
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
        print(f"Data loaded from {filename}")
        return data
    except FileNotFoundError:
        print(f"File {filename} not found.")
        return None

def print_help():
    """Print available commands."""
    print("Available commands:")
    print("  help         - Show this help message")
    print("  encrypt      - Encrypt a message")
    print("  decrypt      - Decrypt a message")
    print("  setbits      - Set the number of bits for prime generation")
    print("  showkeys     - Show the current public and private keys")
    print("  savemessage  - Save an encrypted message to a file")
    print("  loadmessage  - Load an encrypted message from a file")
    print("  showconfig   - Show the current configuration")
    print("  resetkeys    - Regenerate keys with the current bit length")
    print("  exit         - Exit the program")

def main():
    bits = 64  # Default number of bits
    public, private, p, q, n, phi, e, d = generate_keypair(bits)
    start_time = time.time()
    
    print("RSA Encryption/Decryption")
    print("Type 'help' for a list of commands.")
    
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
        
        else:
            print("Unknown command. Type 'help' for a list of commands.")

if __name__ == "__main__":
    main()
