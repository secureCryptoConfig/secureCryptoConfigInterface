package org.securecryptoconfig;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.securecryptoconfig.JSONReader.CryptoUseCase;
import org.securecryptoconfig.SecureCryptoConfig.SCCAlgorithm;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;

/**
 * Class representing a container of a key used for cryptography operations like
 * symmetric or asymmetric encryption.
 * 
 * <br>
 * <br>
 * SCCKey contains a byte[] representation of a key as well as different
 * parameters like the type ({@link SCCKey.KeyType}) and the used algorithm for
 * key creation.
 * 
 * <br>
 * <br>
 * A new {@link SCCKey} for performing a cryptographic use case can be created
 * with the method {@link SCCKey#createKey(KeyUseCase)}. <br>
 * E.g. creating a key for symmetric encryption:
 * 
 * <pre>
 * {
 * 	&#64;code
 * 	SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
 * }
 * </pre>
 * 
 * Choose a suitable {@link SCCKey.KeyUseCase} for key creation. For doing
 * asymmetric encryption use {@link SCCKey.KeyUseCase#AsymmetricEncryption}.
 * <br>
 * For doing symmetric encryption {@link SCCKey.KeyUseCase#SymmetricEncryption}.
 * <br>
 * For Signing {@link SCCKey.KeyUseCase#Signing}<br>
 * <br>
 * Alternatively when performing symmetric encryption it is also possible to
 * create a key derived from a password with
 * {@link SCCKey#createSymmetricKeyWithPassword(byte[])}:
 * 
 * <pre>
 * {
 * 	&#64;code
 * 	SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);
 * }
 * </pre>
 * 
 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
 * with {@link SCCKey#createFromExistingKey(byte[])}:
 *
 * <pre>
 * {@code
 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
 * }
 * </pre>
 *
 */
public class SCCKey extends AbstractSCCKey {

	private static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager.getLogger(SCCKey.class);

	/**
	 * Type of the corresponding key.
	 * 
	 * Depending on the {@link KeyType} a key can only be used for specific use
	 * cases: {@code Symmetric} needed for symmetric encryption/decryption and
	 * {@code Asymmetric} needed for asymmetric en/decryption and signing.
	 */
	public enum KeyType {
		Symmetric, Asymmetric
	}

	/**
	 * Different use cases for which a key can be created.
	 * 
	 * Different KeyUseCases lead to a {@link SCCKey} with a different
	 * {@link KeyType}
	 */
	public enum KeyUseCase {
		SymmetricEncryption, AsymmetricEncryption, Signing
	}

	private static String standardError = "Key could not be created!";

	/**
	 * {@inheritDoc}
	 */
	@Override
	public KeyType getKeyType() {
		return this.type;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getAlgorithm() {
		return this.algorithm;
	}

	/**
	 * Constructor which gets the {@link KeyType}, the byte[] representation of the
	 * public and private key and the algorithm of its creation.
	 * 
	 * This constructor is used in for SCCKeys of {@link KeyType#Asymmetric}. If a
	 * new SCCKey should be created call {@link #createKey(KeyUseCase)}.
	 * 
	 * @param type:       choice of {@link KeyType}
	 * @param publicKey:  byte[] representation of public key
	 * @param privateKey: byte[] representation of private key
	 * @param algorithm:  used for key creation
	 */
	protected SCCKey(KeyType type, byte[] publicKey, byte[] privateKey, String algorithm) {
		super(type, publicKey, privateKey, algorithm);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] toBytes() throws SCCException {
		if (this.type == KeyType.Symmetric) {
			return this.publicKey;
		} else {
			throw new SCCException(
					"Wrong key type for this method. Not symmetric! Call getPublicKeyBytes() or getPrivateKeyBytes()",
					new InvalidKeyException());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] getPublicKeyBytes() throws SCCException {
		if (type == KeyType.Asymmetric) {
			return this.publicKey;
		} else {
			throw new SCCException(
					"Wrong key type for this method. Not asymmetric: no publicKey existing! Call toBytes() to get byte[] representation of key",
					new InvalidKeyException());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public byte[] getPrivateKeyBytes() throws SCCException {
		if (type == KeyType.Asymmetric) {
			return this.privateKey;
		} else {
			throw new SCCException("Wrong key type for this method. Not asymmetric: no privateKey existing!",
					new InvalidKeyException());
		}
	}

	/**
	 * Returns byte[] representation of key to SecretKey for further processing
	 * 
	 * @return SecretKey
	 * @throws SCCException
	 */
	protected SecretKey getSecretKey() throws SCCException {
		if (this.type == KeyType.Symmetric) {
			return new SecretKeySpec(publicKey, 0, publicKey.length, this.algorithm);
		} else {
			throw new SCCException("Wrong key type for this method. Not symmetric!", new InvalidKeyException());
		}
	}

	/**
	 * Returns byte[] representation of public key to PublicKey for further
	 * processing
	 * 
	 * @return PublicKey
	 * @throws SCCException
	 */
	protected PublicKey getPublicKey() throws SCCException {
		if (this.type == KeyType.Asymmetric) {
			try {
				return KeyFactory.getInstance(this.algorithm).generatePublic(new X509EncodedKeySpec(this.publicKey));
			} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
				throw new SCCException("Could not convert to Public Key", e);
			}
		} else {
			throw new SCCException("Wrong KeyType", new InvalidKeyException());
		}
	}

	/**
	 * Returns byte[] representation of private key to PrivateKey for further
	 * processing
	 * 
	 * @return PrivateKey
	 * @throws SCCException
	 */
	protected PrivateKey getPrivateKey() throws SCCException {
		if (this.type == KeyType.Asymmetric) {
			try {
				return KeyFactory.getInstance(this.algorithm).generatePrivate(new PKCS8EncodedKeySpec(this.privateKey));
			} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
				logger.warn("Privatey key invalid or algorithm invalid", e);
				throw new SCCException("Cannot get private key", new InvalidKeyException());
			}
		} else {
			throw new SCCException("Wrong KeyType", new InvalidKeyException());
		}
	}

	/**
	 * Create a key for a specific {@link KeyUseCase}.
	 * 
	 * <br>
	 * <br>
	 * Depending of specified {@link KeyUseCase} the resulting SCCKey can be used
	 * for different provided methods.
	 * 
	 * <br>
	 * <br>
	 * A new {@link SCCKey} for performing a cryptographic use case can be created
	 * with the method {@link SCCKey#createKey(KeyUseCase)}. <br>
	 * E.g. creating a key for symmetric encryption:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	SCCKey key = SCCKey.createKey(KeyUseCase.SymmetricEncryption);
	 * }
	 * </pre>
	 * 
	 * Choose a suitable {@link SCCKey.KeyUseCase} for key creation. For doing
	 * asymmetric encryption use {@link SCCKey.KeyUseCase#AsymmetricEncryption}.
	 * <br>
	 * For doing symmetric encryption {@link SCCKey.KeyUseCase#SymmetricEncryption}.
	 * <br>
	 * For Signing {@link SCCKey.KeyUseCase#Signing}<br>
	 * <br>
	 * Alternatively when performing symmetric encryption it is also possible to
	 * create a key derived from a password with
	 * {@link SCCKey#createSymmetricKeyWithPassword(byte[])}:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	SCCKey key = SCCKey.createSymmetricKeyWithPassword(password);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}:
	 *
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 *
	 * 
	 * @param useCase: for which Scenario is the key needed? Give a value of
	 *                 {@link KeyUseCase}
	 * @return SCCKey: key that can be used for the specified use case
	 * @throws SCCException
	 */
	public static SCCKey createKey(KeyUseCase useCase) throws SCCException {
		CryptoUseCase c;
		switch (useCase) {
		case Signing:
			c = CryptoUseCase.Signing;
			return createNewKeyPair(c);
		case AsymmetricEncryption:
			c = CryptoUseCase.AsymmetricEncryption;
			return createNewKeyPair(c);
		case SymmetricEncryption:
			return createSymmetricKey();
		default:
			return null;
		}
	}

	/**
	 * Creation of a key that can be used for
	 * {@link SecureCryptoConfigInterface#encryptSymmetric(AbstractSCCKey, byte[])}.
	 * 
	 * @return SCCKey
	 * @throws SCCException
	 */
	private static SCCKey createSymmetricKey() throws SCCException {

		if (SecureCryptoConfig.usedAlgorithm == null) {

			ArrayList<SCCAlgorithm> algorithms = SecureCryptoConfig.currentSCCInstance.getUsage()
					.getSymmetricEncryption();

			for (int i = 0; i < algorithms.size(); i++) {

				SCCAlgorithm sccalgorithmID = algorithms.get(i);

				if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {
					return decideForAlgoSymmetric(sccalgorithmID);

				}

			}
		} else {
			return decideForAlgoSymmetric(SecureCryptoConfig.usedAlgorithm);

		}
		throw new SCCException("No supported algorithms! Key creation not possible!", new CoseException(null));

	}

	/**
	 * Auxilliary method for creating a symmetric key
	 * 
	 * @return SCCKey
	 * @throws SCCException
	 */
	private static SCCKey createSymmetricKey(String algo, int keysize) throws SCCException {
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance(algo);
			keyGen.init(keysize);
			SecretKey key = keyGen.generateKey();
			return new SCCKey(KeyType.Symmetric, key.getEncoded(), null, algo);
		} catch (NoSuchAlgorithmException e) {
			throw new SCCException("Key could not be created as no algorithm is specified!", e);
		}
	}

	/**
	 * Auxiliary method for creating asymmetric SCCKey for asymmetric encryption or
	 * signing.
	 * 
	 * @param c
	 * @return SCCKey
	 * @throws SCCException
	 */
	private static SCCKey createNewKeyPair(CryptoUseCase c) throws SCCException {

		if (SecureCryptoConfig.usedAlgorithm == null) {
			ArrayList<SCCAlgorithm> algorithms;

			if (c.equals(CryptoUseCase.AsymmetricEncryption)) {
				algorithms = SecureCryptoConfig.currentSCCInstance.getUsage().getAsymmetricEncryption();

			} else if (c.equals(CryptoUseCase.SymmetricEncryption)) {
				algorithms = SecureCryptoConfig.currentSCCInstance.getUsage().getSymmetricEncryption();

			} else {
				algorithms = SecureCryptoConfig.currentSCCInstance.getUsage().getSigning();

			}

			for (int i = 0; i < algorithms.size(); i++) {

				SCCAlgorithm sccalgorithmID = algorithms.get(i);

				if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {
					return decideForAlgoAsym(sccalgorithmID);

				}

			}
		} else {
			return decideForAlgoAsym(SecureCryptoConfig.usedAlgorithm);

		}
		throw new SCCException(standardError, new CoseException(null));
	}

	private static SCCKey createOneKey(AlgorithmID id, String algoKey) throws SCCException {
		try {
			OneKey oneKey = OneKey.generateKey(id);
			return new SCCKey(KeyType.Asymmetric, oneKey.AsPublicKey().getEncoded(), oneKey.AsPrivateKey().getEncoded(),
					algoKey);
		} catch (CoseException e) {
			throw new SCCException(standardError, e);
		}
	}

	/**
	 * Auxiliary method for creating SCCKey with specific size for asymmetric
	 * encryption.
	 * 
	 * @param algo
	 * @param keysize
	 * @return SCCKey
	 * @throws SCCException
	 */
	private static SCCKey createAsymmetricKey(String algo, int keysize) throws SCCException {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algo);
			keyPairGenerator.initialize(keysize);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			return new SCCKey(KeyType.Asymmetric, keyPair.getPublic().getEncoded(), keyPair.getPrivate().getEncoded(),
					algo);

		} catch (NoSuchAlgorithmException e) {
			throw new SCCException("No such algorithm!", e);
		}
	}

	/**
	 * Creation of key derived from a given password that can be used for symmetric
	 * encryption based on Secure Crypto Config file. <br>
	 * This can be done as follows:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	SCCKey key = SCCKey.createSymmetricKeyWithPassword(passwordBytes);
	 * }
	 * </pre>
	 * 
	 * Also it is possible to create a SCCKey from already existing SCCKey byte[]
	 * with {@link SCCKey#createFromExistingKey(byte[])}:
	 *
	 * <pre>
	 * {@code
	 * SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * @param password: as byte[]
	 * @return SCCKey
	 * @throws SCCException
	 */
	public static SCCKey createSymmetricKeyWithPassword(byte[] password) throws SCCException {
		try {
			return createSymmetricKeyWithPassword(new PlaintextContainer(password));

		} catch (SCCException e) {
			logger.warn("Error in Creation of symmetric key", e);
			throw new SCCException("Error in Creation of symmetric key", e);
		}
	}

	/**
	 * Creation of key derived from a given password that can be used for symmetric
	 * encryption based on Secure Crypto Config file. <br>
	 * This can be done as follows:
	 * 
	 * <pre>
	 * {
	 * 	&#64;code
	 * 	SCCKey key = SCCKey.createSymmetricKeyWithPassword(passwordString);
	 * }
	 * </pre>
	 * 
	 * @param password: as PlaintextContainer
	 * @return SCCKey
	 * @throws SCCException
	 */
	public static SCCKey createSymmetricKeyWithPassword(PlaintextContainer password) throws SCCException {

		if (SecureCryptoConfig.usedAlgorithm == null) {

			ArrayList<SCCAlgorithm> algorithms = SecureCryptoConfig.currentSCCInstance.getUsage()
					.getSymmetricEncryption();

			for (int i = 0; i < algorithms.size(); i++) {

				SCCAlgorithm sccalgorithmID = algorithms.get(i);

				if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {
					return decideForAlgoPassword(sccalgorithmID, password);

				}
			}
		} else {
			return decideForAlgoPassword(SecureCryptoConfig.usedAlgorithm, password);

		}

		throw new SCCException("No supported algorithms! Key creation not possible!", new CoseException(null));
	}

	/**
	 * Auxilliary method for creating key with password with specified parameters
	 * 
	 * @param password
	 * @param algo
	 * @param keyAlgo
	 * @param keysize
	 * @param iterations
	 * @param saltLength
	 * @return SCCKey
	 * @throws SCCException
	 */
	private static SCCKey createKeyWithPassword(PlaintextContainer password, String algo, String keyAlgo, int keysize,
			int iterations, int saltLength) throws SCCException {
		try {
			byte[] salt = generateRandomByteArray(saltLength);

			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
			KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(
					password.toString(StandardCharsets.UTF_8).toCharArray(), salt, iterations, keysize);
			SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
			SecretKey key = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), keyAlgo);
			return new SCCKey(KeyType.Symmetric, key.getEncoded(), null, keyAlgo);
		} catch (NoSuchAlgorithmException e) {
			throw new SCCException("Key could not be created! No algorithm specified!", e);
		} catch (InvalidKeySpecException e) {
			throw new SCCException(standardError, e);
		}
	}

	/**
	 * Still work in progress! <br>
	 * <br>
	 * TODO still needs to be adapted<br>
	 * Method for decoding the <b>{@link SCCKey} object</b> to a byte[]
	 * representation.
	 * 
	 * <br>
	 * <br>
	 * This byte[] can be used to restore a {@link SCCKey} object later again with
	 * the method {@link SCCKey#createFromExistingKey(byte[])}.
	 * 
	 * <pre>
	 * {@code
	 * 	SCCKey key = SCCKey.createFromExistingKey(existingSCCKey)
	 * }
	 * </pre>
	 * 
	 * @return byte[]: representation of SCCKey object
	 */
	public byte[] decodeObjectToBytes() {

		try {
			return SCCInstanceKey.createSCCInstanceKey(this.type, this.publicKey, this.privateKey, this.algorithm);

		} catch (JsonProcessingException e) {
			logger.warn("Error while processing JSON", e);
			return new byte[0];
		}
	}

	/**
	 * Still work in progress! <br>
	 * <br>
	 * TODO still needs to be adapted<br>
	 * Method to create a {@link SCCKey} object out of a existing byte[] SCCKey
	 * representation. <br>
	 * <br>
	 * A byte[] representation of a {@link SCCKey} object can created by calling
	 * {@link SCCKey#decodeObjectToBytes()} on the corresponding SCCKey object.
	 * 
	 * @param existingSCCKey: byte[] representation of a {@link SCCKey} object
	 * @return {@link SCCKey}
	 */
	public static SCCKey createFromExistingKey(byte[] existingSCCKey) {
		ObjectMapper objectMapper = new ObjectMapper();
		SCCInstanceKey sccInstanceKey = null;
		try {
			sccInstanceKey = objectMapper.readValue(existingSCCKey, SCCInstanceKey.class);
		} catch (IOException e) {
			logger.warn("Error while accessing key", e);
		}

		if (sccInstanceKey != null) {
			return new SCCKey(sccInstanceKey.getType(), sccInstanceKey.getPublicKey(), sccInstanceKey.getPrivateKey(),
					sccInstanceKey.getAlgorithm());

		} else {
			return null;
		}
	}

	/**
	 * Generate byte[] with secure Random number generator
	 * 
	 * @param length
	 * @return byte[]
	 */
	private static byte[] generateRandomByteArray(int length) {
		try {
			final byte[] nonce = new byte[length];
			SecureRandom random;
			random = SecureRandom.getInstanceStrong();
			random.nextBytes(nonce);
			return nonce;
		} catch (NoSuchAlgorithmException e) {
			logger.warn("Secure Random Algorithm invalid/unknown", e);
			return new byte[0];
		}

	}

	/**
	 * Auxiliary method for SCCKey generation for asymmetric en/decryption based on determined algorithm
	 * @param sccalgorithmID
	 * @return
	 * @throws SCCException
	 */
	private static SCCKey decideForAlgoAsym(SCCAlgorithm sccalgorithmID) throws SCCException {
		AlgorithmID id;
		String algoKey;
		switch (sccalgorithmID) {
		// Asymmetric
		case RSA_ECB:
		case RSA_SHA_256:
		case RSA_SHA_512:
			return createAsymmetricKey("RSA", 4096);

		// Signing
		case ECDSA_512:
			id = AlgorithmID.ECDSA_512;
			algoKey = "EC";
			return createOneKey(id, algoKey);

		case ECDSA_256:
			id = AlgorithmID.ECDSA_256;
			algoKey = "EC";
			return createOneKey(id, algoKey);
		case ECDSA_384:
			id = AlgorithmID.ECDSA_384;
			algoKey = "EC";
			return createOneKey(id, algoKey);

		default:
			break;
		}
		throw new SCCException(standardError, new CoseException(null));
	}

	/**
	 * Auxiliary method for SCCKey generation with password based on determined algorithm
	 * @param sccalgorithmID
	 * @param password
	 * @return
	 * @throws SCCException
	 */
	private static SCCKey decideForAlgoPassword(SCCAlgorithm sccalgorithmID, PlaintextContainer password)
			throws SCCException {
		String algo = null;
		String keyAlgo = null;
		int keysize = 0;
		int iterations = 0;
		int saltLength = 0;

		String standardAlgo = "PBKDF2WithHmacSHA512";

		switch (sccalgorithmID) {
		case AES_GCM_192_96:
			algo = standardAlgo;
			keyAlgo = "AES";
			keysize = 192;
			iterations = 10000;
			saltLength = 64;
			break;
		case AES_GCM_256_96:
			algo = standardAlgo;
			keyAlgo = "AES";
			keysize = 256;
			iterations = 10000;
			saltLength = 64;
			break;

		case AES_GCM_128_96:
			algo = standardAlgo;
			keyAlgo = "AES";
			keysize = 128;
			iterations = 10000;
			saltLength = 64;
			break;
		default:
			break;
		}

		return createKeyWithPassword(password, algo, keyAlgo, keysize, iterations, saltLength);

	}

	/**
	 * Auxiliary method for SCCKey generation for symmetric en/decryption based on determined algorithm
	 * @param sccalgorithmID
	 * @return
	 * @throws SCCException
	 */
	private static SCCKey decideForAlgoSymmetric(SCCAlgorithm sccalgorithmID) throws SCCException {

		String algo = null;
		int keysize = 0;

		switch (sccalgorithmID) {
		case AES_GCM_192_96:
			algo = "AES";
			keysize = 192;
			break;
		case AES_GCM_256_96:
			algo = "AES";
			keysize = 256;
			break;
		case AES_GCM_128_96:
			algo = "AES";
			keysize = 128;
			break;
		default:
			break;

		}

		return createSymmetricKey(algo, keysize);

	}

}
