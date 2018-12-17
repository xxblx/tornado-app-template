
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

Signing key bytes and salt are encoded with base64 before sending. Salt, opslimit and memlimit are needed for key derivation. 

### How to create key for signing key bytes encryption
Use key derivation. 
* Get the key's password. Get blake2b hash of user's password and use the result as password for secretbox key. 
* Get random salt, opslimit, memlmit and create the key with password from previous step. 
* Get nonce and encrypt signing key bytes.
* Encode the result with base64. 

## Tokens
### Access tokens pair
Access token has two parts: select\_token and verify\_token. 
* Select_token is saved in db as is (plain text). Use it when you need to find specific document in DB.
* Verify\_token isn't stored directly in DB. The webapp creates blake2b hash with secret hmac key of verify\_token and save the hash to DB. Only the webapp knows the secret hmac key. That's why in case when a thief is able to read a content of your database (e.g. via an injection) a thief will steal only hashes. The hash is useless without the secret key. 
* Access tokens pair has an expires time.
### Renew token
It is used for getting new access tokens pair when expires time is over. 

## Auth and api access 
* Get a token with your username and password.
* You have to sign verify_token with your signing key when accessing the api, the webapp will check signature with your verify key. 
* If you don't have signing key on current device you can get encrypted signing key bytes with your username and password, decrypt the bytes and restore a signing key.

See client.py script for example.

You are able to remove using of the tokens signing from the code if you don't want to use this feature. 
