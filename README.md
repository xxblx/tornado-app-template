
Template for [Tornado](https://github.com/tornadoweb/tornado) Web Application. 

# Features
* Cookie-based auth
* Token-based auth
* It uses [PyNaCl](https://github.com/pyca/pynacl/) (python binding to libsodium) for encrypting, hashing and signing
* It uses [Motor](https://github.com/mongodb/motor/) (async python driver for MongoDB)

Tested with Python 3.6.3, Tornado 4.5.3, PyNaCl 1.2.1, Motor 1.2.0.

# API
## Signup
Send to server
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
* Select_token is saved in db as is (plain text). It uses for find queries to DB.
* Verify\_token isn't stored directly the database as plain text. The webapp creates blake2b hash with secret hmac key from verify\_token and save the hash to DB. Only the webapp knows the secret hmac key. So, if someone is be able to read your database (for example - with an injection) he can steal only the hash. The hash is useless without the secret key. 
* Access tokens pair has an expires time.
### Renew token
It uses for getting the new pair when an expires time is over. 

## Auth and api access 
* Get token with your username and password.
* You need sign verify_token with your signing key when access the api and the webapp will check signature with your verify key. 
* If you don't have signing key on current device you can get encrypted signing key bytes with the username and the password, decrypt the bytes and restore signing key.

See client.py script for example.

You are able to remove using of the tokens signing from the code if you don't want to use the feature. 
