import nacl.public
import nacl.encoding

def generate_key_pair():
    # Generate a new private key
    private_key = nacl.public.PrivateKey.generate()
    
    # Extract the public key
    public_key = private_key.public_key
    
    # Convert keys to hexadecimal for compatibility with C++
    private_key_hex = private_key.encode(encoder=nacl.encoding.HexEncoder).decode()
    public_key_hex = public_key.encode(encoder=nacl.encoding.HexEncoder).decode()
    
    return private_key_hex, public_key_hex

if __name__ == "__main__":
    private_key, public_key = generate_key_pair()
    print(f"Private Key (Hex): {private_key}")
    print(f"Public Key (Hex): {public_key}")