# QuickCryptoProd

## Motive
Quick and heavy load-friendly encryption for database, with a different key per message.

## How does it work?

It uses SHA256 + AES-256-GCM to cipher messages. No strange crypto®.

### Initialization of QCP
You have to provide a Base 64 passphrase, with at least 256 bits of entropy. 
You can generate them with Keepass for example.

You **MUST** store each key and key id outside of this library securely, or you will loose access
to encrypted messages.

You **MUST** ensure each passphrase you use is at least 256bit long of entropy. Any less and an attacker could try a bruteforce attack to decipher messages. With great powers come great responsability.

### Key and IV generation (inside)
A different nonce is provided for each message. Nonce is random, generated automagically for you, and at least 256 bits long.
```
Key = SHA-256(passPhrase + nonce)

IV = SHA-256(Key)
```

### Message encryption
We generate a new nonce automagically (to be sure not to reuse a nonce), then the key, an IV; and cipher the message with them using AES-256-GCM.

Then, the encrypted output message looks like:

```
<int keyId>;<Base64 byte[] nonce>;<Base64 byte[] encryptedMessage>
```

### Message decryption
We get the nonce from the encrypted message; then with the static passphrase, we compute the key and the nonce like above.

## Usage

### Singleton initialization
`passPhrase` being your static passphrase, with `id` ID number
```
QuickCryptoProd quickCryptoProdInstance = QuickCryptoProd.getInstance();
quickCryptoProd.setKeyIndex(id);
quickCryptoProdInstance.generateKeychain(passPhrase);
```
### Encryption - once initialized
`message` being the cleartext to cipher, `encrypted` being the encrypted payload like above. 
```
String encrypted = quickCryptoProdInstance.encryptMessage(message);
```

### Decryption - once initialized
`result` being the cleartext, `chiffre` being the encrypted message formatted like above.
```
String result = quickCryptoProdInstance.decryptMessage(chiffre);
```


## License
Apache 2.0, see ./LICENSE

