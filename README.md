# DuckTailDecrypter
C# class to decode and decrypt the DuckTail malware configuration, including the **Telegram Token**, **ChaiID** and list of the **attacker's mail addresses** used to perform **Facebook Business hijacking** attacks.

The configuration file is stored in a resources of the DuckTail DLL, named **profile**, that contains a JSON structure with two entities named **k** and **v**. 
The **k** object is a Base64-encoded AES-CBC key, that is used to decrypt the **v** object, after decoding it from Base64. 

The encryption is performed using the external package **Org.BouncyCastle.Crypto**.

![alt text](https://github.com/Microv/DuckTailDecrypter/blob/main/ducktailconfig.png)

# DuckTailDecrypter
C# class to decrypt strings stored in the DuckTail binary.

![alt text](https://github.com/Microv/DuckTailDecrypter/blob/main/dicktailstrings.png)
