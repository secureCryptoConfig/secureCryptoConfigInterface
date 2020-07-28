# Secure Crypto Config Interface

*Java Interface that provides methods for most common cryptographic use cases. The Interface provides a cryptographic API that is secure and easy to use.*

## Index

1. [Example Usage](#example-usage)
2. [Introduction](#introduction)
3. [Overview](#overview)
4. [Getting started](#getting-started)
5. [En/decryption](#en/decryption)
	1. [Generating new keys](#generating-new-keys)
	2. [Symmetric Encryption](#symmetric-encryption)
	3. [Asymmetric Encryption](#asymmetric-encryption)
	4. [PlaintextContainer](#plaintextcontainer)
	5. [SCCCiphertext](#sccciphertext)
6. [Signing](#signing)
	1. [SCCSignature](#sccsignature)
7. [Hashing](#hashing)
	1. [SCCHash](#scchash)
8. [Password Hashing](#password-hashing)
	1. [SCCPasswordHash](#sccpasswordhash)
9. [Handling of Secure Crypto Config files](#handling-of-secure-crypto-config-files)
10.[Specification of algorithms](#specification-of-algorithms)

## Example Usage 

Code for Encryption (and decryption) with the Secure Crypto Config Interface (which automatically selects a secure (symmetric in this case) cryptography algorithm and parameters.

```java
byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);

SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
SecureCryptoConfig scc = new SecureCryptoConfig();

// Encryption
SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);

// Decryption
PlaintextContainer plain = scc.decryptSymmetric(key, ciphertext);
byte[] decrypted = plain.toBytes();
```

## Introduction

Choosing secure cryptography algorithms and their corresponding parameters is difficult. Also, current cryptography APIs cannot change their default configuration which renders them inherently insecure. The Secure Crypto Config provides a method that allows cryptography libraries to change the default cryptography algorithms over time and at the same time stay compatible with previous cryptography operations. This is achieved by combining three things standardized by the Secure Crypto Config:
- A process that should be repeated regulary where a new set of default configurations for standardized cryptography primitives is published in a specific format.
- A Secure Crypto Config Interface that describes a common API to use cryptography primitives in software
- Using [COSE](https://github.com/cose-wg/COSE-JAVA) to derive the parameters from output of cryptography primitives, otherwise future changes of the default configuration would change existing applications behavior.

The Secure Crypto Config provides a secure API that is secure and easy usable. It provides an abstraction from the underlying algorithm such that the usage gets more convenient and makes misuse and resulting security issues harder to occur. Even for users with not much cryptography experience it offers a possibility to implement secure cryptographic code.

## Overview
The Secure Crypto Config Interface provides methods for the most common cryptographic use cases: Symmetric encryption, Asymmetric encryption, hashing, password hashing and Signing. The algorithms used for for the internal execution of the invoked use case is determined by the content of the Secure Crypto Config files. These JSON formatted files are provided within the Interface bt can also be customized as long as the internal structure stays the same. With the release of a new version of the Interface the files will be updated to use only currently secure algorithms and parameters. In this way the burden of making right choices for parameters and algorithms to implement secure code can be lifted from the user.

For handling the result of the cryptographic use cases we make use of a adapted version of [COSE](https://github.com/cose-wg/COSE-JAVA) to derive the parameters from output of cryptography primitives. Otherwise future changes of the default configuration would change existing applications behavior. Therefore the output is a byte representation of a corresponding COSE message which contains not only the actual output (e.g. ciphertext, hash) but also all used parameters.


## Getting started
To be abel to use the Secure Crypto Config Interface it is necessary to add two differen *jar* files in the build path of your project:
- *jar* file of the Secure Crypto Config Interface
- *jar* file of a adapted version of [COSE](https://github.com/cose-wg/COSE-JAVA)

Before using the Interface it is necessary to handle the import like follows:

```java
import org.securecryptoconfig;
import COSE;
```

## En/Decryption

### Generating new keys

An example for crreating a symmetric key can be performed as follows:

```java
SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
```

It is also possible to create a symmetric key that is derived from a password:
```java
SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);
```

For performing cryptographic use cases a SCCKey is needed. To create a new SCC just call the `createKey(KeyUseCase useCase)`-method. To be able to generate a suitable key it is necessary to define for which use case the key should be created. Possible `KeyUseCase` choices are: `SymmetricEncryption, AsymmetricEncryption, Signing`.
Depending on the defined `KeyUseCase` the key gets a `KeyType` which ist either `Symmetric` or `Asymmetric`. A asymmetric key contains in contrast to the symmetric key a public and a private key.

Usage for SCCKey depending on specified `KeyUseCase`:

- `KeyUseCase.SymmetricEncryption`:`encryptSymmetric(..)`, `reEncryptSymmetric(..)`, `decryptSymmetric(..)`

- `KeyUseCase.AsymmetricEncryption`:`encryptAsymmetric(..)`, `reEncryptAsymmetric(..)`, `decryptAsymmetric(..)`

- `KeyUseCase.Signing`:`sign(..)`, `updateSignature(..)`, `validateSignature(..)`


To get information about the SCCKey different methods exists: `toBytes()`, `getPublicKeyBytes()`, `getPrivateKeyBytes()`, `getAlgorithm()`. They can be invoked on a SCCKey instance.


### Symmetric Encryption

General process of symmetric en/decryption:
```java
byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
SecureCryptoConfig scc = new SecureCryptoConfig();
// Encryption
SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
// Decryption
PlaintextContainer plain = scc.decryptSymmetric(key, ciphertext);
```
 or with convenient methods:
 ```java
byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
PlaintextContainer plain = new PlaintextContainer(plaintext);

SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
// Encryption
SCCCiphertext ciphertext = plain.encryptSymmetric(key);
// Decryption
PlaintextContainer plain = ciphertext.decryptSymmetric(key);
```

Methods provided for symmetric encryption are: `encryptSymmetric(..)`, `reEncryptSymmetric(..)` and `decryptSymmetric(..)`

- `encryptSymmetric(SCCKey key, Plaintext plaintext)`/`encryptSymmetric(SCCKey key, byte[] plaintext)`: As parameter a SCCKey must be given. The `KeyType` of this key must be `Symmetric`. The plaintext can be specified in form of a PlaintextContainer or byte[] representation. The given plaintext will be encrypted. As a result a SCCCiphertext will be returned. It is also possible to invoke the encryption method on a specified PlaintextContainer.

- `decryptSymmetric(SCCKey key, SCCCiphertext sccciphertext)`: As parameter the SCCCiphertext (containing ciphertext and encryption parameters) and the corresponding SCCKey must be specified. Can also be invoked on SCCiphertext.

- `reEncryptSymmetric(SCCKey key, SCCCiphertext ciphertext)`: ReEncrypts a given SCCCiphertext. Ciphertext will be first decrypted and then encrypted again with the current Secure Crypto Config file. Can also be invoked on SCCiphertext.


### Asymmetric Encryption

General process of asymmetric en/decryption:
```java
byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
SecureCryptoConfig scc = new SecureCryptoConfig();
// Encryption
SCCCiphertext ciphertext = scc.encryptAsymmetric(key, plaintext);
// Decryption
PlaintextContainer plain = scc.decryptAsymmetric(key, ciphertext);
```
 or with convenient methods:
 ```java
byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
PlaintextContainer plain = new PlaintextContainer(plaintext);

SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
// Encryption
SCCCiphertext ciphertext = plain.encryptAsymmetric(key);
// Decryption
PlaintextContainer plain = ciphertext.decryptAsymmetric(key);
```

The general process for asymmetric encryption is the same as for symmetric encryption.

Methods provided for asymmetric encryption are: `encryptAymmetric(..)`, `reEncryptAsymmetric(..)` and `decryptAsymmetric(..)`

- `encryptAsymmetric(SCCKey key, Plaintext plaintext)`/`encryptAsymmetric(SCCKey key, byte[] plaintext)`: As parameter a SCCKey must be given. The `KeyType` of this key must be `Asymmetric`. The plaintext can be specified in form of a PlaintextContainer or byte[] representation. The given plaintext will be encrypted. As a result a SCCCiphertext will be returned. It is also possible to invoke the encryption method on a specified PlaintextContainer.

- `decryptAsymmetric(SCCKey key, SCCCiphertext sccciphertext)`: As parameter the SCCCiphertext (containing ciphertext and encryption parameters) and the corresponding SCCKey must be specified. Can also be invoked on SCCiphertext.

- `reEncryptAsymmetric(SCCKey key, SCCCiphertext ciphertext)`: ReEncrypts a given SCCCiphertext. Ciphertext will be first decrypted and then encrypted again with the current Secure Crypto Config file. Can also be invoked on SCCiphertext.

### PlaintextContainer
Represents the plaintext as byte[] not only in case of encryption but also for signing, hashing or password hashing. By expressing the plaintext as a PlaintextContainer the user should be able to perform cryptographic use cases as convenient as possible. The PlaintextContainer class provides convenient methods that can be invoked on a PlaintextContainer instance and therefore make the actions which can be performed with a plaintext more easy. The provided convenient methods are: `toBytes()`, `toString(..)`, `validateHash(..)`, `validatePasswordHash(..)`, `encryptSymmetric(..)`, `encryptAsymmetric(..)`, `sign(..)`,  `hash()`, `passwordHash()`.

### SCCCiphertext

The SCCCipertext represents a byte[] representation of a specific COSE message, that contains the ciphertext as well as all used parameters of the encryption. To be able to decrypt a ciphertext correctly the same parameters as specified for encryption must be used. To be able to guarantee the correct decryption even if configuartions of the API are changing during the time these used parameters must be stored as well as the ciphertext. These necessary informations are represented as SCCiphertext which results from `encryptSymmetric(..)`, `encryptAsymmetric(..)` and is also needed as parameter for later decryption.
This class also contains convenient methods for the user such that methods needing the SCCiphertext can easily invoked on a instance of this class.



## Signing

General process of signing/validation:
```java
byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
SCCKey key = SCCKey.createKey(KeyUseCase.Signing);
SecureCryptoConfig scc = new SecureCryptoConfig();
//Signing
SCCSignature signature = scc.sign(key,plaintext);
//validation
boolean result = scc.validateSignature(key, signature);
```

 or with convenient methods:
 ```java
byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
PlaintextContainer plain = new PlaintextContainer(plaintext);
SCCKey key = SCCKey.createKey(KeyUseCase.Signing);
//Signing
SCCSignature signature = plain.sign(key);
//validation
boolean result = signature.validateSignature(key);
```

Methods provided for Signing are: `sign(..)`, `updateSignature(..)` and `validateSignature(..)`

- `sign(SCCKey key, Plaintext plaintext)`/`sign(SCCKey key, byte[] plaintext)`: As parameter a SCCKey must be given. The `KeyType` of this key must be `Asymmetric`. The plaintext can be specified in form of a PlaintextContainer or byte[] representation. The given plaintext will be encrypted. As a result a SCCSignature will be returned. It is also possible to invoke the method on a specified PlaintextContainer.

- `validateSignature(SCCKey key, SCCSignature signature)`: As parameter the SCCSignature (containing signature and signing parameters) and the corresponding SCCKey must be specified. Can also be invoked on SCCSignature. Returns a boolean. Looks if the signature is valid.

- `updateSignature(SCCKey key, PlaintextContainer plaintext)`: Given a SCCSignature of a plaintext: the corresponding plaintext will be signed again with the current Secure Crypto Config.

### SCCSignature
The SCCSignature is the output after performing signing. It is the same representation as the SCCCiphertext described previously. It represents a byte[] representation of a specific COSE message, that contains the signature as well as all used parameters of the signing process.

## Hashing

General process of hashing and its validation
```java
byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);

SecureCryptoConfig scc = new SecureCryptoConfig();
//Hashing
SCCHash hash = scc.hash(plaintext);
//Validation
boolean result = scc.validateHash(plaintext, hash);
```
 or with convenient methods:
 ```java
byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
PlaintextContainer plain = new PlaintextContainer(plaintext);
//Hashing
SCCHash hash = plain.hash();
//Validation
boolean result = hash.validateHash(plaintext);
```

Methods provided for Hashing are: `hash(..)`, `validateHash(..)` and `updateHash(..)`

- `hash(Plaintext plaintext)`/`hash(byte[] plaintext)`: The plaintext can be specified in form of a PlaintextContainer or byte[] representation. The given plaintext will be hashed. As a result a SCCHash will be returned. It is also possible to invoke the method on a specified PlaintextContainer.

- `validateHash(PlaintextContainer plaintext, SCCHash hash)`/`validateHash(byte[] plaintext, SCCHash hash)`: As parameter the SCCHash (containing hash and parameters) and the corresponding plaintext must be specified. Can also be invoked on SCCHash. Returns a boolean. Look if a given SCCHash is valid: plaintext will be hashed again and compared if resulting hash is identical to the given one.

- `updateHash(PlaintextContainer plaintext, SCCHash hash)`:  Given a SCCHash of a plaintext: the corresponding plaintext will be hashed again with the current Secure Crypto Config. Returns a SCCHash.

### SCCHash
The SCCHash is the output after performing hashing. It is the same representation as the SCCCiphertext or SCCSignature described previously. It represents a byte[] representation of a specific COSE message, that contains the hash as well as all used parameters of the hashing process.

## Password Hashing

General process of password hashing and its validation
```java
byte[] password = "Hello World!".getBytes(StandardCharsets.UTF_8);

SecureCryptoConfig scc = new SecureCryptoConfig();
//Hashing
SCCPasswordHash hash = scc.passwordHash(password);
//Validation
boolean result = scc.validatePasswordHash(password, hash);
```
 or with convenient methods:
 ```java
byte[] password = "Hello World!".getBytes(StandardCharsets.UTF_8);
PlaintextContainer container = new PlaintextContainer(password);
//Hashing
SCCPasswordHash hash = container.passwordHash();
//Validation
boolean result = hash.validatePasswordHash(password);
```
Methods provided for Hashing are: `passwordHash(..)` and `validatePasswordHash(..)`

- `passwordHash(Plaintext password)`/`passwordHash(byte[] password)`: The password can be specified in form of a PlaintextContainer or byte[] representation. The given password will be hashed. As a result a SCCPasswordHash will be returned. It is also possible to invoke the method on a specified PlaintextContainer.

- `validatePasswordHash(PlaintextContainer password, SCCPasswordHash hash)`/`validateHash(byte[] plaintext, SCCHash hash)`: As parameter the SCCPasswordHash (containing hash and parameters) and the corresponding password must be specified. Can also be invoked on SCCPasswordHash. Returns a boolean. Look if a given SCCPasswordHash is valid: password will be hashed again and compared if resulting hash is identical to the given one.

### SCCPasswordHash
The secure storage of passwords requires hashing. Yet, password hashing requires that the hashing can not be performed very fast to prevent attackers from guessing/brute-forcing passwords from leaks or against the live system.
The SCCPasswordHash is the output after performing password hashing. It is the same representation as the SCCHash described previously. It represents a byte[] representation of a specific COSE message, that contains the hash as well as all used parameters of the hashing process.

## Handling of Secure Crypto Config files
The internal execurtion of a cryptographic use case is done according to Secure Crypto Config files. These files contain for each supproted use case unique algorithm ids which represent specific algorithm and parameter choices. By default these informations are parsed out of the Secure Crypto Config files which are provided within the Interface.

It is also possible to give a custom part to your own (derived) versions of the Secure crypto config files. This can be done with the `setPathToSCCDirectory(String path)` mathod by simply giving the path to your directory as a parameter.

By default the files provided by within the Interface are used for parsing. There are files for different *security levels*. The higher the security level of a file the more confidential your data must be handled. By defualt the Interface will use the algorithm ids from the most recent (according to its version) file with the highest security level. If you want a specific file to be parsed use the `setSCCFile(String filePath)` method and give the path to the desired file. Also you can use the `setSecurityLevel(int level)` method. As a result the most recent file with the specified security level number will be used.

The files used for processing can be shown with `getUsedSCC()`. If you have set a specific file for usage or a custom path you can also go back to the default settings with the `setDefaultSCC()` method.

##Specification of algorithms
By default the algorithm used for executing the specified cryptographic use case is determined by the currently used Secure Crypto Config file. It is also possible to chose a specific algorithm from all the supported ones with the method `setAlgorithm(SCCAlgorithm algorithm)`. `SCCAlgorithm` contains the unique algorithm identifiers of all currently supported algorithms for all use cases. To be able to perform a specific use case (e.g. hashing) a suitable algorithm identifier must be choose. This algorithm will be used for all further invoked methods. If the default choice of the Secure Crypto Config should be used again call `defaultAlgorithm()` or for changing to a specific algorithm call `setAlgorithm(SCCAlgorithm algorithm)` again.
