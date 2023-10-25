# DuckTailDecrypter
C# script to decode and decrypt the DuckTail malware configuration, including the Telegram Token, ChaiID and list of the attacker's mail addresses.
The configuration file is stored in a resources of the DuckTAIL DLL, named profile, that contains a JSON file with two entities named k and v. 
The k object is a base64 encodes AES-CBC key, that is used to decrypt the v object, after decoding it from Base64. 
The encryption is performed using the external package Org.BouncyCastle.Crypto.

![alt text](https://github.com/Microv/DuckTailDecrypter/blob/main/ducktailconfig.png)

