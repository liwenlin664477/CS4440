# RSA server

## How to build

```
javac *.java
```

## Run the Server

```
java Server
```

Log was saved to `/tmp/MyServerLogFile.log`

```
Mar 03, 2022 10:56:34 AM Server runServer
INFO: ==== RSA server log ====
[*] Listening on port 1337...
Mar 03, 2022 10:56:39 AM Server runServer
INFO: Got Client's connetion: /127.0.0.1:58724
Public key (Client):MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdT+AShr5QVRkP9EqKCoyn1z2O4lWp26v8Ak8s2OjKld5kthc0r+XnAsatmX1t2ZoT8IOpnBr0r+yVv0daFcTheNcHyipmYgxGODFwRkEtk4qjTiZTd3yD6x177uWYCDiz7H+mYRQ4Ztoi2QYYGv035cwd8JvEWc/1zl/OPaC1iQIDAQAB
Public key's signature: zjZWG7KXTORJtmtPkmqiBwiJ6EPXyKxXU5zoV3tGm9VelXsK8XvWQ7qc3a9jENjXQ4Xf9l/PcNoOGZVvvCY9VWk+gKkSYq4SyAn4MHhAEWWBLoDATqwyapuMqcyOFhgQioQMbN+r57zuljIwHCcLDEGeJvTFHNxTdEh6GNEtpB0=
Mar 03, 2022 10:56:39 AM Server runServer
INFO: Got Client's signature and public key
 (+20)
Signature check: true
Mar 03, 2022 10:56:39 AM Server runServer
INFO: Client's Signature (1) verification passed
(+20)
Mar 03, 2022 10:56:39 AM Server runServer
INFO: Client's Signature (2) verification passed
 (+20)
Aes decrypted successfully
Mar 03, 2022 10:56:39 AM Server runServer
INFO: Decryption of Client's message succeeded.
 (+20)
Server connection closed
Mar 03, 2022 10:56:39 AM Server runServer
INFO: Connection closed.
 (+20)
========
[*] Listening on port 1337...

```

## Run Client

```
java Client

```

Example of output text:

```
Got Client's connetion: /127.0.0.1:58724
==== RSA ====
Private key's length: 848
Public key's length:216
Signature: zjZWG7KXTORJtmtPkmqiBwiJ6EPXyKxXU5zoV3tGm9VelXsK8XvWQ7qc3a9jENjXQ4Xf9l/PcNoOGZVvvCY9VWk+gKkSYq4SyAn4MHhAEWWBLoDATqwyapuMqcyOFhgQioQMbN+r57zuljIwHCcLDEGeJvTFHNxTdEh6GNEtpB0=
[+] Client's sending public_key + signature
Encrypted AES key: 0Mb2kREyy6HRsvjjEEGt9qJLuVXf+ARIgQbJmlBl6Pt2+xkIKLKEdbaeECPRMgWJwskqTSkf9ALF9cesxGublx5wKf3jUHe/rJnA/DiToJB+TwE3DmXzx3CJQOgtlGKUZTD4+OPFRU4MVh/MeAA9pUQ0LqK/H5aGQabQ7/IXIEM=
Server signature is valid
[+] Client received Server's AES key: 1234567890123456
[+] Client received Server's Random String: pcfgppbrcv
[+] enString: 2bf770fbe574f66d9245f19a936871b2
[+] Client IP from server: /127.0.0.1:58724
[+] Received server's sig: WxrRi177R2qRQKfYweaaO/TRW0wpvaQSD9CqkZxLrocKTAqH4TuRjFneUQq7FOTtHEwqZBf4NTKyPCp4tPpDoUIcTp3lGOmZSKHKwUYohgzYmeroObrPa04kPTb2ls4N3xrXS1IwhPhmdrPG6JAIzmPbkYAygbYt556+7oYZLDY=
[+] Received server's message: OK.
[+] Pass.

```
