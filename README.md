# Library
A C# library for Ares.lol using RSA asymmetrical encryption.

# Encryption
To provide the best security we use asymmetrical encryption with RSA-4096

The client generates a public key/private key pair; then, it encrypts a message containing its public key using the server's public key. The server then decrypts that using its private key and responds with a message encrypted using the client's public key.

![Alice and Bob example](https://bjc.edc.org/March2019/bjc-r/img/3-lists/525px-Public_key_encryption.png)

# Streaming
If you want to stream simply call the `Module` function on an authenticated `Ares` object.
```
Ares.SecureImage SecureImage = Session.Module("a590b336-ff74-477b-9564-93ba8d30118e");

int[] DecryptedImage = SecureImage.Decrypt();

// Work with the image
```

# Variables
To get a variable simply call the `Variable` function on an authenticated `Ares` object.
```
string VariableContent = Session.Variable("window-shopper");
```

# Ares.lol
Ares.lol is a authentication system with a focus on security and quality.
[Check it out](https://ares.lol)
