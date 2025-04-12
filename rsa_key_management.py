from Crypto.PublicKey import RSA

# Generate RSA Key Pair
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Save RSA Keys to Files
def save_rsa_keys(private_key, public_key, private_file="private.pem", public_file="public.pem"):
    with open(private_file, "wb") as priv_file:
        priv_file.write(private_key)
    with open(public_file, "wb") as pub_file:
        pub_file.write(public_key)

# Load RSA Keys from Files
def load_rsa_keys(private_file="private.pem", public_file="public.pem"):
    with open(private_file, "rb") as priv_file:
        private_key = RSA.import_key(priv_file.read())
    with open(public_file, "rb") as pub_file:
        public_key = RSA.import_key(pub_file.read())
    return private_key, public_key
