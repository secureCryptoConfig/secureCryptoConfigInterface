/**
 * The Secure Crypto Config Interface provides methods for the most common cryptographic use 
 * cases: <b>Symmetric encryption, Asymmetric encryption, hashing, password hashing 
 * and Signing</b>. The algorithms used for for the internal execution of the invoked use
 * case is determined by the content of the Secure Crypto Config files. With the release
 * of a new version of the Interface the files will be updated to use only currently secure 
 * algorithms and parameters. Therefore, it is necessary to update the SecureCryptoConfig
 * library as soon as possible if a new version is provided to be able to be up-to-date
 *  with the current security standard. In this way the burden of making right choices 
 *  for parameters and algorithms to implement secure code can be lifted from the user.
 *  <br><br>
 * For implementing different use cases the most important methods can be found at {@link org.securecryptoconfig.SecureCryptoConfig}.
 * First create a instance of {@link org.securecryptoconfig.SecureCryptoConfig} and invoke the corresponding method for
 * the specific cryptographic use case that should be implemented. 
 * <br><br>
 * One of the most importatnt use cases provided is the symmetric en/decryption. 
 * This can be realized with the Secure Crypto Config as follows:
 * <pre>
 * {@code
 * byte[] plaintext = "Hello World!".getBytes(StandardCharsets.UTF_8);
 * SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
 * SecureCryptoConfig scc = new SecureCryptoConfig();
 * // Encryption
 * SCCCiphertext ciphertext = scc.encryptSymmetric(key, plaintext);
 * // Decryption
 * PlaintextContainer plain = scc.decryptSymmetric(key, ciphertext);
 * }
 *</pre>
 */
package org.securecryptoconfig;
