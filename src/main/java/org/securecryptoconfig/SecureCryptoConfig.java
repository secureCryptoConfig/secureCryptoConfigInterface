package org.securecryptoconfig;

import java.nio.charset.StandardCharsets;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import org.securecryptoconfig.SCCKey.KeyType;
import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.AsymMessage;
import COSE.Attribute;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HashMessage;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.PasswordHashMessage;
import COSE.Sign1Message;

/**
 * <b> Starting point for performing every cryptographic use case.</b> The class
 * contains methods for performing symmetric/asymmetric en/decryption,
 * (password) hashing and signing.
 * 
 * Implements the {@link SecureCryptoConfigInterface}.
 * 
 * To perform the desired use case simply create a new SecureCryptoConfig object
 * and call the specific method: E.g. hashing
 * 
 * <pre>
 * {
 * 	{@code
 * 	SecureCryptoConfig scc = new SecureCryptoConfig();
 * 	SCCHash sccHash = scc.hash(plaintext);
 * }
 * </pre>
 * 
 * @author Lisa
 *
 */
public class SecureCryptoConfig implements SecureCryptoConfigInterface {

	private static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager
			.getLogger(SecureCryptoConfig.class);

	protected static SCCInstance currentSCCInstance = JSONReader.parseFiles(null);

	protected static SCCAlgorithm usedAlgorithm = null;

	protected static boolean customPath = false;

	private static String standardError = "No supported algorithm!";
	private static String coseError = "Error with COSE";

	/**
	 * Contains all supported algorithm names
	 *
	 */
	public enum SCCAlgorithm {
		// symmetric:
		AES_GCM_256_96, AES_GCM_128_96, AES_GCM_192_96,
		// Digital Signature
		ECDSA_512, ECDSA_256, ECDSA_384,
		// Hash
		SHA_512, SHA_256, SHA3_512, SHA3_256,
		// asymmetric:
		RSA_SHA_512, RSA_SHA_256, RSA_ECB,
		// PasswordHash
		PBKDF_SHA_512, PBKDF_SHA_256, // SHA 512 with 64 salt
		SHA_512_64
	}

	/**
	 * Set the latest Secure Crypto Config file of a specific Security level for
	 * usage.
	 * 
	 * <br>
	 * <br>
	 * Algorithms that are used for executing the invoked cryptographic use case are
	 * looked up in the latest Secure Crypto Config file (according to its version)
	 * with the specified Security level
	 * 
	 * @param level: integer of desired security level of Secure Crypto Config file
	 * @throws IllegalArgumentException there are no files with the specified level
	 */
	public static void setSecurityLevel(int level) {
		if (JSONReader.levels.contains(level)) {
			currentSCCInstance = JSONReader.getLatestSCC(level);
		} else {
			throw new IllegalArgumentException("There are no files with the specified Security Level");
		}
	}

	/**
	 * Return the policy name of the Secure Crypto Config file that is currently
	 * used for executing cryptographic use case
	 * 
	 * @return policyName: policy name of the used Secure Crypto Config file
	 */
	public static String getUsedSCC() {
		return currentSCCInstance.getPolicyName();
	}

	/**
	 * Set path to a custom root folder "scc-configs" which contains the Secure
	 * Crypto Config files.
	 * 
	 * <br>
	 * <br>
	 * To use the default Secure Config files at "src/scc-configs" again call
	 * {@link SecureCryptoConfig#setDefaultSCC()}
	 * 
	 * @param path: path to "scc-configs" directory
	 * @throws InvalidPathException Path is not existing
	 */
	public static void setCustomSCCPath(Path path) {
		customPath = true;

		if (path.toFile().exists()) {
			JSONReader.isJAR = false;
			currentSCCInstance = JSONReader.parseFiles(path);

		} else {
			throw new InvalidPathException(path.toString(), "Path is not existing");
		}

	}

	/**
	 * Set Secure Crypto Config file (with the specified policy name) to use. To use
	 * the default Secure Config files at "src/scc-configs" again call
	 * {@link SecureCryptoConfig#setDefaultSCC()}
	 * 
	 * @param policyName: policy name of the Secure Crypto Config file to use
	 * @throws InvalidParameterException policy name is not existing in any file
	 */
	public static void setSCCFile(String policyName) {
		SCCInstance instance = JSONReader.findPathForPolicy(policyName);
		if (instance != null) {
			currentSCCInstance = instance;
		} else {
			throw new InvalidParameterException("PolicyName not existing");
		}

	}

	/**
	 * Go back to the usage of Secure Crypto Config files at "src/scc-configs"
	 * included inside the library. Only necessary if a custom path with
	 * {@link #setCustomSCCPath(Path)} or {@link #setSCCFile(String)} was called
	 * before.
	 */
	public static void setDefaultSCC() {
		customPath = false;
		currentSCCInstance = JSONReader.parseFiles(null);
	}

	/**
	 * Put all values from AlgorithmIDEnum in a Set
	 * 
	 * @return hashSet
	 */
	protected static HashSet<SCCAlgorithm> getEnums() {
		HashSet<SCCAlgorithm> values = new HashSet<>();
		Collections.addAll(values, SCCAlgorithm.values());

		return values;
	}

	/**
	 * Set a specific algorithm for the execution of the later performed use cases.
	 * Possible choices are contained in {@link SCCAlgorithm} <br>
	 * E.g.
	 * 
	 * <pre>
	 * {@code
	 * SecureCryptoConfig.setAlgorithm(SCCAlgorithm.AES_GCM_256_96);
	 * }
	 * </pre>
	 * 
	 * To use the default algorithm from the included Secure Crypto Config files
	 * again call {@link #defaultAlgorithm()}
	 * 
	 * @param algorithm: one supported algorithm from {@link SCCAlgorithm}
	 * 
	 */
	public static void setAlgorithm(SCCAlgorithm algorithm) {
		usedAlgorithm = algorithm;
	}

	/**
	 * Use the algorithms proposed in the currently used Secure Crypto Config file
	 * for the execution of the use cases. Only necessary if specific algorithm was
	 * set previously via {@link #setAlgorithm(SCCAlgorithm)}
	 */
	public static void defaultAlgorithm() {
		usedAlgorithm = null;
	}
	
	/**
	 * Return currently used algorithm id for realizing crypto primitive
	 * @return
	 */
	public static SCCAlgorithm getAlgorithm()
	{
		return usedAlgorithm;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCCiphertext encryptSymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws SCCException {

		if (key.getKeyType() == KeyType.Symmetric) {
			if (usedAlgorithm == null) {

				ArrayList<SCCAlgorithm> algorithms = currentSCCInstance.getUsage().getSymmetricEncryption();

				for (int i = 0; i < algorithms.size(); i++) {

					SCCAlgorithm sccalgorithmID = algorithms.get(i);

					if (getEnums().contains(sccalgorithmID)) {
						return decideForAlgoSymmetric(sccalgorithmID, key, plaintext);
					}
				}
			} else {
				return decideForAlgoSymmetric(usedAlgorithm, key, plaintext);
			}
		} else {
			throw new SCCException(
					"The used SCCKey has the wrong KeyType for this use case. Create a key with KeyType.Symmetric",
					new InvalidKeyException("Invalid key!"));
		}
		throw new SCCException("No supported algorithms!", new CoseException(null));

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCCiphertext encryptSymmetric(AbstractSCCKey key, byte[] plaintext) throws SCCException {

		return encryptSymmetric(key, new PlaintextContainer(plaintext));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCCiphertext reEncryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext) throws SCCException {

		PlaintextContainer decrypted = decryptSymmetric(key, ciphertext);
		return encryptSymmetric(key, decrypted);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PlaintextContainer decryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws SCCException {
		if (key.getKeyType() == KeyType.Symmetric) {
			try {
				Encrypt0Message msg = (Encrypt0Message) COSE.Message.DecodeFromBytes(sccciphertext.msg);
				return new PlaintextContainer(msg.decrypt(key.toBytes()));
			} catch (CoseException e) {
				throw new SCCException(standardError, e);
			}
		} else {
			throw new SCCException(
					"The used SCCKey has the wrong KeyType for this use case. Create a key with KeyType.Symmetric",
					new InvalidKeyException());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCCiphertext encryptAsymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws SCCException {

		if (key.getKeyType() == KeyType.Asymmetric) {
			if (usedAlgorithm == null) {

				ArrayList<SCCAlgorithm> algorithms = currentSCCInstance.getUsage().getAsymmetricEncryption();

				for (int i = 0; i < algorithms.size(); i++) {

					SCCAlgorithm sccalgorithmID = algorithms.get(i);

					if (getEnums().contains(sccalgorithmID)) {
						return decideForAlgoAsymmetric(sccalgorithmID, key, plaintext);
					}

				}
			} else {
				return decideForAlgoAsymmetric(usedAlgorithm, key, plaintext);

			}
		} else {
			throw new SCCException("The used SCCKey has the wrong KeyType for this use case.",
					new InvalidKeyException());
		}
		throw new SCCException("No supported algorithm", new CoseException(null));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCCiphertext encryptAsymmetric(AbstractSCCKey key, byte[] plaintext) throws SCCException {

		return encryptAsymmetric(key, new PlaintextContainer(plaintext));

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCCiphertext reEncryptAsymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext) throws SCCException {
		PlaintextContainer decrypted = decryptAsymmetric(key, ciphertext);
		return encryptAsymmetric(key, decrypted);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public PlaintextContainer decryptAsymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws SCCException {
		if (key.getKeyType() == KeyType.Asymmetric) {
			SCCKey k = (SCCKey) key;

			AsymMessage msg;
			try {
				msg = (AsymMessage) COSE.Message.DecodeFromBytes(ciphertext.msg);
				return new PlaintextContainer(msg.decrypt(new KeyPair(k.getPublicKey(), k.getPrivateKey())));
			} catch (CoseException e) {
				throw new SCCException("Error by decoding of bytes", e);
			}
		} else {
			throw new SCCException("The used SCCKey has the wrong KeyType for this use case.",
					new InvalidKeyException());
		}

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCHash hash(PlaintextContainerInterface plaintext) throws SCCException {

		if (usedAlgorithm == null) {

			ArrayList<SCCAlgorithm> algorithms = currentSCCInstance.getUsage().getHashing();

			for (int i = 0; i < algorithms.size(); i++) {

				SCCAlgorithm sccalgorithmID = algorithms.get(i);

				if (getEnums().contains(sccalgorithmID)) {
					return decideForAlgoHash(sccalgorithmID, plaintext);
				}

			}
		} else {
			return decideForAlgoHash(usedAlgorithm, plaintext);
		}
		throw new SCCException(standardError, new CoseException(null));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCHash hash(byte[] plaintext) throws SCCException {

		return hash(new PlaintextContainer(plaintext));

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCHash updateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws SCCException {
		return hash(plaintext);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCHash updateHash(byte[] plaintext, AbstractSCCHash hash) throws SCCException {
		return updateHash(new PlaintextContainer(plaintext), hash);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws SCCException {
		SCCHash sccHash = (SCCHash) hash;
		try {
			String s = new String(sccHash.convertByteToMsg().getHashedContent(), StandardCharsets.UTF_8);

			SCCHash hash1 = hash(plaintext);
			String s1 = new String(hash1.convertByteToMsg().getHashedContent(), StandardCharsets.UTF_8);

			return s.equals(s1);
		} catch (CoseException e) {
			throw new SCCException("Valiating of hash could not be performed", e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validateHash(byte[] plaintext, AbstractSCCHash hash) throws SCCException {
		return validateHash(new PlaintextContainer(plaintext), hash);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCSignature sign(AbstractSCCKey key, PlaintextContainerInterface plaintext) throws SCCException {
		if (key.getKeyType() == KeyType.Asymmetric) {

			if (usedAlgorithm == null) {

				ArrayList<SCCAlgorithm> algorithms = currentSCCInstance.getUsage().getSigning();

				for (int i = 0; i < algorithms.size(); i++) {
					SCCAlgorithm sccalgorithmID = algorithms.get(i);

					if (getEnums().contains(sccalgorithmID)) {
						return decideForAlgoSigning(sccalgorithmID, key, plaintext);
					}

				}
			} else {
				return decideForAlgoSigning(usedAlgorithm, key, plaintext);
			}
		} else {
			throw new SCCException("The used SCCKey has the wrong KeyType for this use case. ",
					new InvalidKeyException());
		}
		throw new SCCException(standardError, new CoseException(null));

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCSignature sign(AbstractSCCKey key, byte[] plaintext) throws SCCException {

		return sign(key, new PlaintextContainer(plaintext));

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCSignature updateSignature(AbstractSCCKey key, PlaintextContainerInterface plaintext) throws SCCException {
		return sign(key, plaintext);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCSignature updateSignature(AbstractSCCKey key, byte[] plaintext) throws SCCException {
		return updateSignature(key, new PlaintextContainer(plaintext));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validateSignature(AbstractSCCKey key, AbstractSCCSignature signature) throws SCCException {
		if (key.getKeyType() == KeyType.Asymmetric) {
			SCCKey k = (SCCKey) key;
			PrivateKey privateKey = null;
			try {
				SCCSignature s = (SCCSignature) signature;
				Sign1Message msg = s.convertByteToMsg();

				// Check if privateKey is empty and construct key accorsing to result
				boolean privateKeyExists = privateKeyEmpty(k);

				if (privateKeyExists) {
					OneKey oneKey = new OneKey(k.getPublicKey(), privateKey);
					return msg.validate(oneKey);
				} else {
					OneKey oneKey = new OneKey(k.getPublicKey(), null);
					return msg.validate(oneKey);
				}
			} catch (CoseException e) {
				throw new SCCException("Signature validation could not be performed!", e);
			}

		} else {
			throw new SCCException("The used SCCKey has the wrong KeyType for this use case. ",
					new InvalidKeyException());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validateSignature(AbstractSCCKey key, byte[] signature) throws SCCException {
		return validateSignature(key, SCCSignature.createFromExistingSignature(signature));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCPasswordHash passwordHash(PlaintextContainerInterface password) throws SCCException {

		if (usedAlgorithm == null) {

			ArrayList<SCCAlgorithm> algorithms = currentSCCInstance.getUsage().getPasswordHashing();

			for (int i = 0; i < algorithms.size(); i++) {

				SCCAlgorithm sccalgorithmID = algorithms.get(i);

				if (getEnums().contains(sccalgorithmID)) {
					return decideForAlgoPasswordHash(sccalgorithmID, password);
				}

			}
		} else {
			return decideForAlgoPasswordHash(usedAlgorithm, password);
			
		}
		throw new SCCException(standardError, new CoseException(null));

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public SCCPasswordHash passwordHash(byte[] password) throws SCCException {

		return passwordHash(new PlaintextContainer(password));

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validatePasswordHash(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws SCCException {

		SCCPasswordHash sccHash = (SCCPasswordHash) passwordhash;
		PasswordHashMessage msg = sccHash.convertByteToMsg();
		CBORObject algX = msg.findAttribute(HeaderKeys.Algorithm);
		try {
			AlgorithmID alg = AlgorithmID.FromCBOR(algX);

			SCCPasswordHash hash = SecureCryptoConfig.createPasswordHashMessageSalt(password, alg, msg.getSalt());

			String hash1 = new String(msg.getHashedContent(), StandardCharsets.UTF_8);

			if (hash != null) {
				String hash2 = new String(hash.convertByteToMsg().getHashedContent(), StandardCharsets.UTF_8);

				return hash1.equals(hash2);
			} else {
				return false;
			}
		} catch (CoseException e) {
			throw new SCCException("Could not validate password hash", new CoseException(null));
		}

	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean validatePasswordHash(byte[] password, AbstractSCCPasswordHash passwordhash) throws SCCException {
		return validatePasswordHash(new PlaintextContainer(password), passwordhash);
	}

	/**
	 * Creation of COSE Sign1Message for signing.
	 * 
	 * @param plaintext
	 * @param key
	 * @param id
	 * @return SCCSignature
	 * @throws SCCException
	 */
	protected static SCCSignature createSignMessage(PlaintextContainerInterface plaintext, AbstractSCCKey key,
			AlgorithmID id) throws SCCException {
		Sign1Message m = new Sign1Message();
		m.SetContent(plaintext.toBytes());
		SCCKey k = (SCCKey) key;
		try {
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			OneKey oneKey = new OneKey(k.getPublicKey(), k.getPrivateKey());
			m.sign(oneKey);

			return SCCSignature.createFromExistingSignature(m.EncodeToBytes());
		} catch (CoseException e) {
			throw new SCCException("Signing could not be performed!", e);
		}
	}

	/**
	 * Creation of COSE AsymMessage for asymmetric Encryption.
	 * 
	 * @param plaintext
	 * @param id
	 * @param key
	 * @return SCCCiphertext
	 * @throws SCCException
	 * @throws IllegalStateException
	 */
	protected static SCCCiphertext createAsymMessage(PlaintextContainerInterface plaintext, AlgorithmID id,
			AbstractSCCKey key) throws SCCException {
		try {
			SCCKey k = (SCCKey) key;
			AsymMessage asymMsg = new AsymMessage();
			asymMsg.SetContent(plaintext.toBytes());
			asymMsg.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			asymMsg.encrypt(new KeyPair(k.getPublicKey(), k.getPrivateKey()));
			asymMsg.SetContent((byte[]) null);

			return SCCCiphertext.createFromExistingCiphertext(asymMsg.EncodeToBytes());
		} catch (CoseException e) {
			throw new SCCException("Asymmetric encryption could not be performed", e);
		}
	}

	/**
	 * Creation of COSE PasswordHashMessage for password hashing with existing salt
	 * value.
	 * 
	 * @param password
	 * @param id
	 * @param salt
	 * @return SCCPasswordHash
	 * @throws SCCException
	 */
	protected static SCCPasswordHash createPasswordHashMessageSalt(PlaintextContainerInterface password, AlgorithmID id,
			byte[] salt) throws SCCException {
		try {
			PasswordHashMessage m = new PasswordHashMessage();
			m.SetContent(password.toBytes());
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m.passwordHashWithSalt(salt);
			m.SetContent((byte[]) null);
			return SCCPasswordHash.createFromExistingPasswordHash(m.EncodeToBytes());
		} catch (CoseException e) {
			logger.warn("COSE Exception", e);
			return null;
		}
	}

	/**
	 * Creation of COSE PasswordHashMessage for password Hashing.
	 * 
	 * @param password
	 * @param id
	 * @return SCCPasswordHash
	 * @throws SCCException
	 */
	protected static SCCPasswordHash createPasswordHashMessage(PlaintextContainerInterface password, AlgorithmID id)
			throws SCCException {

		try {
			PasswordHashMessage m = new PasswordHashMessage();
			m.SetContent(password.toBytes());
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m.passwordHash();
			m.SetContent((byte[]) null);
			return SCCPasswordHash.createFromExistingPasswordHash(m.EncodeToBytes());

		} catch (CoseException e) {
			logger.warn(coseError, e);
			return null;
		}
	}

	/**
	 * Creation of COSE HashMessage for hashing.
	 * 
	 * @param plaintext
	 * @param id
	 * @return SCCHash
	 * @throws SCCException
	 */
	protected static SCCHash createHashMessage(PlaintextContainer plaintext, AlgorithmID id) throws SCCException {
		try {
			HashMessage hashMessage = new HashMessage();
			hashMessage.SetContent(plaintext.toBytes());

			hashMessage.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);

			hashMessage.hash();
			hashMessage.SetContent((byte[]) null);
			return SCCHash.createFromExistingHash(hashMessage.EncodeToBytes());

		} catch (CoseException e) {
			logger.warn(coseError, e);
			return null;
		}
	}

	/**
	 * Creation of COSE Encrypt0Message for symmetric Encryption.
	 * 
	 * @param plaintext
	 * @param key
	 * @param id
	 * @return SCCCiphertext
	 * @throws SCCException
	 */
	protected static SCCCiphertext createMessage(PlaintextContainerInterface plaintext, AbstractSCCKey key,
			AlgorithmID id) throws SCCException {
		try {
			Encrypt0Message encrypt0Message = new Encrypt0Message();
			encrypt0Message.SetContent(plaintext.toBytes());

			encrypt0Message.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);

			encrypt0Message.encrypt(key.publicKey);
			encrypt0Message.SetContent((byte[]) null);

			return SCCCiphertext.createFromExistingCiphertext(encrypt0Message.EncodeToBytes());

		} catch (CoseException e) {
			logger.warn(coseError, e);
			return null;
		}
	}

	private static boolean privateKeyEmpty(SCCKey k) throws SCCException {
		try {
			k.getPrivateKey();
			return false;
		} catch (NullPointerException e) {
			return true;

		}
	}

	/**
	 * Auxiliary method for SCCCiphertext generation for symmetric en/decryption based on determined algorithm
	 * @param sccalgorithmID
	 * @param key
	 * @param plaintext
	 * @return
	 * @throws SCCException
	 */
	private static SCCCiphertext decideForAlgoSymmetric(SCCAlgorithm sccalgorithmID, AbstractSCCKey key,
			PlaintextContainerInterface plaintext) throws SCCException {
		switch (sccalgorithmID) {
		case AES_GCM_256_96:
			return SecureCryptoConfig.createMessage(plaintext, key, AlgorithmID.AES_GCM_256);
		case AES_GCM_128_96:
			return SecureCryptoConfig.createMessage(plaintext, key, AlgorithmID.AES_GCM_128);
		case AES_GCM_192_96:
			return SecureCryptoConfig.createMessage(plaintext, key, AlgorithmID.AES_GCM_192);
		default:
			break;

		}
		throw new SCCException("No supported algorithms!", new CoseException(null));

	}

	/**
	 * Auxiliary method for SCCCiphertext generation for asymmetric en/decryption based on determined algorithm
	 * @param sccalgorithmID
	 * @param key
	 * @param plaintext
	 * @return
	 * @throws SCCException
	 */
	private static SCCCiphertext decideForAlgoAsymmetric(SCCAlgorithm sccalgorithmID, AbstractSCCKey key,
			PlaintextContainerInterface plaintext) throws SCCException {
		switch (sccalgorithmID) {
		case RSA_SHA_512:
			return SecureCryptoConfig.createAsymMessage(plaintext, AlgorithmID.RSA_OAEP_SHA_512, key);
		case RSA_SHA_256:
			return SecureCryptoConfig.createAsymMessage(plaintext, AlgorithmID.RSA_OAEP_SHA_256, key);
		case RSA_ECB:
			return SecureCryptoConfig.createAsymMessage(plaintext, AlgorithmID.RSA_ECB, key);
		default:
			break;
		}
		throw new SCCException("No supported algorithm", new CoseException(null));
	}

	/**
	 * Auxiliary method for SCCSignature generation based on determined algorithm
	 * @param sccalgorithmID
	 * @param key
	 * @param plaintext
	 * @return
	 * @throws SCCException
	 */
	private static SCCSignature decideForAlgoSigning(SCCAlgorithm sccalgorithmID, AbstractSCCKey key,
			PlaintextContainerInterface plaintext) throws SCCException {
		switch (sccalgorithmID) {
		case ECDSA_512:
			return SecureCryptoConfig.createSignMessage(plaintext, key, AlgorithmID.ECDSA_512);
		case ECDSA_256:
			return SecureCryptoConfig.createSignMessage(plaintext, key, AlgorithmID.ECDSA_256);
		case ECDSA_384:
			return SecureCryptoConfig.createSignMessage(plaintext, key, AlgorithmID.ECDSA_384);
		default:
			break;
		}

		throw new SCCException(standardError, new CoseException(null));

	}
	
	private static SCCPasswordHash decideForAlgoPasswordHash(SCCAlgorithm sccalgorithmID, PlaintextContainerInterface password) throws SCCException {

		switch (sccalgorithmID) {
		case PBKDF_SHA_512:
			return SecureCryptoConfig.createPasswordHashMessage(password, AlgorithmID.PBKDF_SHA_512);
		case PBKDF_SHA_256:
			return SecureCryptoConfig.createPasswordHashMessage(password, AlgorithmID.PBKDF_SHA_256);
		case SHA_512_64:
			return SecureCryptoConfig.createPasswordHashMessage(password, AlgorithmID.SHA_512_64);
		default:
			break;
		}
		throw new SCCException(standardError, new CoseException(null));
	}
	
	private static SCCHash decideForAlgoHash(SCCAlgorithm sccalgorithmID, PlaintextContainerInterface plaintext) throws SCCException {
		PlaintextContainer p;
		switch (sccalgorithmID) {
		case SHA_512:
			p = new PlaintextContainer(plaintext.toBytes());
			return SecureCryptoConfig.createHashMessage(p, AlgorithmID.SHA_512);
		case SHA_256:
			p = new PlaintextContainer(plaintext.toBytes());
			return SecureCryptoConfig.createHashMessage(p, AlgorithmID.SHA_256);
		case SHA3_512:
			p = new PlaintextContainer(plaintext.toBytes());
			return SecureCryptoConfig.createHashMessage(p, AlgorithmID.SHA3_512);
		case SHA3_256:
			p = new PlaintextContainer(plaintext.toBytes());
			return SecureCryptoConfig.createHashMessage(p, AlgorithmID.SHA3_256);

		default:
			break;
		}
		throw new SCCException(standardError, new CoseException(null));
		
	}
}
