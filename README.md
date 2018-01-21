
This is a template for Tornado web application with token-based auth. 

* Python3
* [Tornado](https://github.com/tornadoweb/tornado)
* [PyNaCl](https://github.com/pyca/pynacl/) - python binding to libsodium
* [Motor](https://github.com/mongodb/motor/) - async python driver for MongoDB

# How it works
## Signup
Send to server:
* username
* password
* encrypted signing key (private key) bytes
* verify key (public key) hex
* salt
* opslimit
* memlimit

Signing key bytes and salt are encoded with base64 before sending. Salt, opslimit and memlimit are need for key derivation. 

### How to create key for signing key bytes encryption
Use key derivation. 
* Get key password. Use blake2b hash from user's password as password for secretbox key. 
* Get random salt, opslimit, memlmit and create key with key's password. 
* Get nonce and encrypt signing key bytes.
* Encode the result with base64. 

## Tokens
### Access tokens pair
Access token splits into two parts: select\_token and verify\_token. 
* Select_token saves in db as is. It uses for find queries to DB.
* Verify\_token doesn't saves in db directly. The webapp creates blake2b hash with secret hmac key from verify\_token and save it to DB. Only the webapp knows the secret hmac key. If someone will be able to read yours DB (with injection for example) he still can only hash without choice to get natural verify_token. 
* Access tokens pair has some expires time.
### Renew token
It can be used for getting new access tokens pair when expires time is over. 

## Auth and api access 
* Get token with yours username and password.
* When access to api you need sign verify_token with your signing key and the webapp will check signification with yours verify key restored from verify key hex. 
* If you don't have signing key on current device you can get encrypted signing key bytes with yours username and password, decrypt the bytes and restore signing key.

See client.py script for example.

You can remove signing keys using from the code if you don't need that and use only access tokens pair in auth process.

