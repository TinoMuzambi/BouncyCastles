# NIS Practical

This repository is the source documents for the NIS 2022 Practical. Implementing a client server communication protocol that implements end-to-end encryption using the [BouncyCastlesFips library](https://www.bouncycastle.org/fips-java/).

## Files

The following Java class files can be found under the src directory:

| Class                | Description                                                                                           |
|----------------------|-------------------------------------------------------------------------------------------------------|
| Utils                | Utils for running the client server setup.                                                            |
| KeyWithMessageDigest | A class for wrapping a signed one time key with a signed message digest.                              |
| Hashing              | A class for testing the hashing and signing flow.                                                     |
| Encryption           | A class for testing the encryption flow.                                                              |
| HashingAndEncryption | A class for testing the full flow including hashing, signing and encryption methods.                  |
| ClientHandler        | This class helps the server keep track of all connected clients.                                      |
| Client               | This class represents the client in a client-server network.                                          |
| ClientRunner         | Creates a key pair for a Client then runs a new instance of a Client passing in the key pair encoded. |
| Server               | This class represents the server in a client-server network.                                          |

## Compiling and Running

There is a Makefile in the root of the repository to make running the client-server network easy. In order to setup a network you can run the following commands in separate terminals:

```
make
make server
make client
make client
```

## Docs

Javadocs can also be generated by running ``make docs``. This will generate documentation in the doc directory. Opening the index.html file will open a webpage with documentation for all the classes in the repository.

## Usage

Once the server is running, each new client will request a name. Once the name is granted, the client is connected and can send/receive messages from the group.

## Authors

- Sihle Calana - CLNSIH001
- Simangaliso Mncwango - MNCSIM006
- Tinotenda Muzambi - MZMTIN002
- Tumo Masire - MSRTUM001
