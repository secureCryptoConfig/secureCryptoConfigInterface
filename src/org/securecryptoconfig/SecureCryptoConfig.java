package org.securecryptoconfig;

import java.nio.charset.StandardCharsets;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
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
 * Encapsulates Cryptography Use Cases, Configuration, and Parsing Logic of the
 * Secure Crypto Config.
 * 
 * Implements the {@link SecureCryptoConfigInterface}.
 * 
 * @author Lisa
 *
 */
public class SecureCryptoConfig implements SecureCryptoConfigInterface {

	protected static SCCInstance currentSCCInstance = JSONReader.parseFiles(null);
	//protected static SCCInstance currentSCCInstance = null;
	protected static SCCAlgorithm usedAlgorithm = null;

	public static boolean customPath = false;

	/**
	 * All supported algorithm names
	 *
	 */
	public static enum SCCAlgorithm {
		// symmetric:
		AES_GCM_256_96, AES_GCM_128_96,
		// Digital Signature
		ECDSA_512,
		// Hash
		SHA_512,
		// asymmetric:
		RSA_SHA_512,
		// PasswordHash
		PBKDF_SHA_256
	}

	/**
	 * Set the latest Secure Crypto Config file of a specific Security level for
	 * usage.
	 * 
	 * Algorithms that are used for executing the invoked cryptographic use case are
	 * looked up in the latest Secure Crypto Config file (according to its version)
	 * with the specified Security level
	 * 
	 * @param level: integer of desired security level of Secure Crypto Config file
	 * @throws IllegalArgumentException
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
	 * used to look up algorithms to use for executing cryptographic use case
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
	 * @param path: path to "scc-config" directory
	 * @throws InvalidPathException
	 */
	public static void setCustomSCCPath(Path path) {
		customPath = true;
		/*
		 * if (path.toFile().exists()) { sccPath =
		 * JSONReader.parseFiles(path.toString()); } else { throw new
		 * InvalidPathException(path.toString(), "Path is not existing"); }
		 */
	}

	/**
	 * Set Secure Crypto Config file to use
	 * 
	 * @param policyName: policy name of the Secure Crypto Config file to use
	 * @throws InvalidPathException
	 */
	public static void setPolicy(String policyName) {
		SCCInstance instance = JSONReader.findPathForPolicy(policyName);
		if (instance != null) {
			currentSCCInstance = instance;
		} else {
			throw new InvalidParameterException("PolicyName not existing");
		}

	}

	/**
	 * Set default Secure Crypto Configuration using Secure Crypto Config files at
	 * "src/scc-configs" Only necessary if a custom path with
	 * {@link #setCustomSCCPath(Path)} or {@link #setPolicy(String)} was called
	 * before
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
		HashSet<SCCAlgorithm> values = new HashSet<SCCAlgorithm>();

		for (SCCAlgorithm c : SCCAlgorithm.values()) {
			values.add(c);
		}

		return values;
	}

	/**
	 * Set a specific algorithm for the execution of the later performed use cases.
	 * Possible choices are containes in {@link SCCAlgorithm}
	 * 
	 * @param algorithm: choice of one specific supported algorithm for the
	 *        following performed use cases.
	 * 
	 */
	public static void setAlgorithm(SCCAlgorithm algorithm) {
		usedAlgorithm = algorithm;
	}

	/**
	 * Use the algorithms proposed in the currently used Secure Crypto Config file
	 * for the execution of the performed use cases. Only necessary if specific
	 * algorithm was set previously via
	 * {@link SecureCryptoConfig#setAlgorithm(AlgorithmID)}
	 */
	public static void defaultAlgorithm() {
		usedAlgorithm = null;
	}

	@Override
	public SCCCiphertext encryptSymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException, InvalidKeyException {

		if (key.getKeyType() == KeyType.Symmetric) {
			if (usedAlgorithm == null) {
				ArrayList<SCCAlgorithm> algorithms = new ArrayList<SCCAlgorithm>();

				algorithms = currentSCCInstance.getUsage().getSymmetricEncryption();

				for (int i = 0; i < algorithms.size(); i++) {

					SCCAlgorithm sccalgorithmID = algorithms.get(i);

					if (getEnums().contains(sccalgorithmID)) {

						switch (sccalgorithmID) {
						case AES_GCM_256_96:
							return SecureCryptoConfig.createMessage(plaintext, key, AlgorithmID.AES_GCM_256);
						case AES_GCM_128_96:
							return SecureCryptoConfig.createMessage(plaintext, key, AlgorithmID.AES_GCM_128);
						default:
							break;

						}
					}
				}
			} else {
				switch (usedAlgorithm) {
				case AES_GCM_256_96:
					return SecureCryptoConfig.createMessage(plaintext, key, AlgorithmID.AES_GCM_256);
				case AES_GCM_128_96:
					return SecureCryptoConfig.createMessage(plaintext, key, AlgorithmID.AES_GCM_128);
				default:
					break;

				}

			}
		} else {
			throw new InvalidKeyException("The used SCCKey has the wrong KeyType for this use case. "
					+ "Create a key with KeyType.Symmetric");
		}
		throw new CoseException("No supported algorithms!");
	}

	@Override
	public SCCCiphertext encryptSymmetric(AbstractSCCKey key, byte[] plaintext)
			throws CoseException, InvalidKeyException {

		return encryptSymmetric(key, new PlaintextContainer(plaintext));
	}

	@Override
	public SCCCiphertext reEncryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext ciphertext)
			throws CoseException, InvalidKeyException {

		PlaintextContainer decrypted = decryptSymmetric(key, ciphertext);
		return encryptSymmetric(key, decrypted);
	}

	@Override
	public PlaintextContainer decryptSymmetric(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws CoseException, InvalidKeyException {
		if (key.getKeyType() == KeyType.Symmetric) {
			try {
				Encrypt0Message msg = (Encrypt0Message) Encrypt0Message.DecodeFromBytes(sccciphertext.msg);
				return new PlaintextContainer(msg.decrypt(key.toBytes()));
			} catch (CoseException e) {
				e.printStackTrace();
				throw new CoseException("No supported algorithm!");
			}
		} else {
			throw new InvalidKeyException("The used SCCKey has the wrong KeyType for this use case. "
					+ "Create a key with KeyType.Symmetric");
		}
	}

	@Override
	public SCCCiphertext encryptAsymmetric(AbstractSCCKey keyPair, PlaintextContainerInterface plaintext)
			throws CoseException, InvalidKeyException, SCCException {

		if (keyPair.getKeyType() == KeyType.Asymmetric) {
			if (usedAlgorithm == null) {
				ArrayList<SCCAlgorithm> algorithms = new ArrayList<SCCAlgorithm>();

				algorithms = currentSCCInstance.getUsage().getAsymmetricEncryption();

				for (int i = 0; i < algorithms.size(); i++) {

					SCCAlgorithm sccalgorithmID = algorithms.get(i);

					if (getEnums().contains(sccalgorithmID)) {

						switch (sccalgorithmID) {
						case RSA_SHA_512:
							return SecureCryptoConfig.createAsymMessage(plaintext, AlgorithmID.RSA_OAEP_SHA_512,
									keyPair);
						default:
							break;
						}
					}

				}
			} else {
				switch (usedAlgorithm) {
				case RSA_SHA_512:
					return SecureCryptoConfig.createAsymMessage(plaintext, AlgorithmID.RSA_OAEP_SHA_512, keyPair);
				default:
					break;
				}
			}
		} else {

			throw new InvalidKeyException("The used SCCKey has the wrong KeyType for this use case. "
					+ "Create a key with KeyType.Asymmetric");
		}
		throw new CoseException("No supported algorithm!");
	}

	@Override
	public SCCCiphertext encryptAsymmetric(AbstractSCCKey keyPair, byte[] plaintext)
			throws CoseException, InvalidKeyException, SCCException {

		return encryptAsymmetric(keyPair, new PlaintextContainer(plaintext));

	}

	@Override
	public SCCCiphertext reEncryptAsymmetric(AbstractSCCKey keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException, InvalidKeyException, SCCException {
		PlaintextContainer decrypted = decryptAsymmetric(keyPair, ciphertext);
		return encryptAsymmetric(keyPair, decrypted);
	}

	@Override
	public PlaintextContainer decryptAsymmetric(AbstractSCCKey keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException, InvalidKeyException, SCCException {
		if (keyPair.getKeyType() == KeyType.Asymmetric) {
			SCCKey pair = (SCCKey) keyPair;

			AsymMessage msg = (AsymMessage) AsymMessage.DecodeFromBytes(ciphertext.msg);
			return new PlaintextContainer(msg.decrypt(new KeyPair(pair.getPublicKey(), pair.getPrivateKey())));
		} else {
			throw new InvalidKeyException("The used SCCKey has the wrong KeyType for this use case. "
					+ "Create a key with KeyType.Asymmetric");
		}

	}

	@Override
	public SCCHash hash(PlaintextContainerInterface plaintext) throws CoseException {

		if (usedAlgorithm == null) {
			ArrayList<SCCAlgorithm> algorithms = new ArrayList<SCCAlgorithm>();

			algorithms = currentSCCInstance.getUsage().getHashing();
			for (int i = 0; i < algorithms.size(); i++) {

				SCCAlgorithm sccalgorithmID = algorithms.get(i);

				if (getEnums().contains(sccalgorithmID)) {

					switch (sccalgorithmID) {
					case SHA_512:
						PlaintextContainer p = new PlaintextContainer(plaintext.toBytes());
						return SecureCryptoConfig.createHashMessage(p, AlgorithmID.SHA_512);
					default:
						break;
					}
				}

			}
		} else {
			switch (usedAlgorithm) {
			case SHA_512:
				PlaintextContainer p = new PlaintextContainer(plaintext.toBytes());
				return SecureCryptoConfig.createHashMessage(p, AlgorithmID.SHA_512);
			default:
				break;
			}
		}
		throw new CoseException("No supported algorithm!");
	}

	@Override
	public SCCHash hash(byte[] plaintext) throws CoseException {
		try {
			return hash(new PlaintextContainer(plaintext));
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public SCCHash updateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException {
		return hash(plaintext);
	}

	@Override
	public SCCHash updateHash(byte[] plaintext, AbstractSCCHash hash) throws CoseException {
		return updateHash(new PlaintextContainer(plaintext), hash);
	}

	@Override
	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException {
		SCCHash sccHash = (SCCHash) hash;
		String s = new String(sccHash.convertByteToMsg().getHashedContent(), StandardCharsets.UTF_8);

		SCCHash hash1 = hash(plaintext);
		String s1 = new String(hash1.convertByteToMsg().getHashedContent(), StandardCharsets.UTF_8);

		return s.equals(s1);
	}

	@Override
	public boolean validateHash(byte[] plaintext, AbstractSCCHash hash) throws CoseException {
		return validateHash(new PlaintextContainer(plaintext), hash);
	}

	@Override
	public SCCSignature sign(AbstractSCCKey keyPair, PlaintextContainerInterface plaintext)
			throws CoseException, InvalidKeyException, SCCException {
		if (keyPair.getKeyType() == KeyType.Asymmetric) {

			if (usedAlgorithm == null) {

				ArrayList<SCCAlgorithm> algorithms = new ArrayList<SCCAlgorithm>();

				algorithms = currentSCCInstance.getUsage().getSigning();

				for (int i = 0; i < algorithms.size(); i++) {
					SCCAlgorithm sccalgorithmID = algorithms.get(i);

					if (getEnums().contains(sccalgorithmID)) {

						switch (sccalgorithmID) {
						case ECDSA_512:
							return SecureCryptoConfig.createSignMessage(plaintext, keyPair, AlgorithmID.ECDSA_512);
						default:
							break;
						}
					}

				}
			} else {
				switch (usedAlgorithm) {
				case ECDSA_512:
					return SecureCryptoConfig.createSignMessage(plaintext, keyPair, AlgorithmID.ECDSA_512);
				default:
					break;
				}
			}
		} else {
			throw new InvalidKeyException("The used SCCKey has the wrong KeyType for this use case. "
					+ "Create a key with KeyType.Asymmetric");
		}
		throw new CoseException("No supported algorithm!");
	}

	@Override
	public SCCSignature sign(AbstractSCCKey keyPair, byte[] plaintext)
			throws CoseException, InvalidKeyException, SCCException {

		return sign(keyPair, new PlaintextContainer(plaintext));

	}

	@Override
	public SCCSignature updateSignature(AbstractSCCKey keyPair, PlaintextContainerInterface plaintext)
			throws CoseException, InvalidKeyException, SCCException {
		return sign(keyPair, plaintext);
	}

	@Override
	public SCCSignature updateSignature(AbstractSCCKey keyPair, byte[] plaintext)
			throws CoseException, InvalidKeyException, SCCException {
		return updateSignature(keyPair, new PlaintextContainer(plaintext));
	}

	@Override
	public boolean validateSignature(AbstractSCCKey keyPair, AbstractSCCSignature signature)
			throws InvalidKeyException, SCCException {
		if (keyPair.getKeyType() == KeyType.Asymmetric) {
			SCCKey pair = (SCCKey) keyPair;
			PrivateKey privateKey = null;
			try {
				SCCSignature s = (SCCSignature) signature;
				Sign1Message msg = s.convertByteToMsg();
				try {
					privateKey = pair.getPrivateKey();
				} catch (NullPointerException e) {
					OneKey oneKey = new OneKey(pair.getPublicKey(), null);
					return msg.validate(oneKey);
				}
				OneKey oneKey = new OneKey(pair.getPublicKey(), privateKey);
				return msg.validate(oneKey);
			} catch (CoseException e) {
				throw new SCCException("Signature validation could not be performed!", e);
			}

		} else {
			throw new InvalidKeyException("The used SCCKey has the wrong KeyType for this use case. "
					+ "Create a key with KeyType.Asymmetric");
		}
	}

	@Override
	public boolean validateSignature(AbstractSCCKey keyPair, byte[] signature)
			throws InvalidKeyException, SCCException {
		return validateSignature(keyPair, SCCSignature.createFromExistingSignature(signature));
	}

	@Override
	public SCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException {

		if (usedAlgorithm == null) {
			ArrayList<SCCAlgorithm> algorithms = new ArrayList<SCCAlgorithm>();

			algorithms = currentSCCInstance.getUsage().getPasswordHashing();

			for (int i = 0; i < algorithms.size(); i++) {

				SCCAlgorithm sccalgorithmID = algorithms.get(i);

				if (getEnums().contains(sccalgorithmID)) {

					switch (sccalgorithmID) {
					case PBKDF_SHA_256:
						return SecureCryptoConfig.createPasswordHashMessage(password, AlgorithmID.PBKDF_SHA_256);
					default:
						break;
					}
				}

			}
		} else {
			switch (usedAlgorithm) {
			case PBKDF_SHA_256:
				return SecureCryptoConfig.createPasswordHashMessage(password, AlgorithmID.PBKDF_SHA_256);
			default:
				break;
			}
		}
		throw new CoseException("No supported algorithm!");

	}

	@Override
	public SCCPasswordHash passwordHash(byte[] password) throws CoseException {
		try {
			return passwordHash(new PlaintextContainer(password));
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public boolean validatePasswordHash(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException {

		SCCPasswordHash sccHash = (SCCPasswordHash) passwordhash;
		PasswordHashMessage msg = sccHash.convertByteToMsg();
		CBORObject algX = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(algX);

		SCCPasswordHash hash = SecureCryptoConfig.createPasswordHashMessageSalt(password, alg, msg.getSalt());

		String hash1 = new String(msg.getHashedContent(), StandardCharsets.UTF_8);
		String hash2 = new String(hash.convertByteToMsg().getHashedContent(), StandardCharsets.UTF_8);

		return hash1.equals(hash2);

	}

	@Override
	public boolean validatePasswordHash(byte[] password, AbstractSCCPasswordHash passwordhash) throws CoseException {
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
		SCCKey pair = (SCCKey) key;
		try {
			m.addAttribute(HeaderKeys.Algorithm, AlgorithmID.ECDSA_512.AsCBOR(), Attribute.PROTECTED);
			OneKey oneKey = new OneKey(pair.getPublicKey(), pair.getPrivateKey());
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
	 * @param keyPair
	 * @return SCCCiphertext
	 * @throws SCCException
	 * @throws IllegalStateException
	 */
	protected static SCCCiphertext createAsymMessage(PlaintextContainerInterface plaintext, AlgorithmID id,
			AbstractSCCKey keyPair) throws SCCException {
		try {
			SCCKey pair = (SCCKey) keyPair;
			AsymMessage asymMsg = new AsymMessage();
			asymMsg.SetContent(plaintext.toBytes());
			asymMsg.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			asymMsg.encrypt(new KeyPair(pair.getPublicKey(), pair.getPrivateKey()));
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
	 */
	protected static SCCPasswordHash createPasswordHashMessageSalt(PlaintextContainerInterface password, AlgorithmID id,
			byte[] salt) {
		try {
			PasswordHashMessage m = new PasswordHashMessage();
			m.SetContent(password.toBytes());
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m.passwordHashWithSalt(salt);
			m.SetContent((byte[]) null);
			return SCCPasswordHash.createFromExistingPasswordHash(m.EncodeToBytes());
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Creation of COSE PasswordHashMessage for password Hashing.
	 * 
	 * @param password
	 * @param id
	 * @return SCCPasswordHash
	 */
	protected static SCCPasswordHash createPasswordHashMessage(PlaintextContainerInterface password, AlgorithmID id) {

		try {
			PasswordHashMessage m = new PasswordHashMessage();
			m.SetContent(password.toBytes());
			m.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);
			m.passwordHash();
			m.SetContent((byte[]) null);
			return SCCPasswordHash.createFromExistingPasswordHash(m.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Creation of COSE HashMessage for hashing.
	 * 
	 * @param plaintext
	 * @param id
	 * @return SCCHash
	 */
	protected static SCCHash createHashMessage(PlaintextContainer plaintext, AlgorithmID id) {
		try {
			HashMessage hashMessage = new HashMessage();
			hashMessage.SetContent(plaintext.toBytes());

			hashMessage.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);

			hashMessage.hash();
			hashMessage.SetContent((byte[]) null);
			return SCCHash.createFromExistingHash(hashMessage.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
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
	 */
	protected static SCCCiphertext createMessage(PlaintextContainerInterface plaintext, AbstractSCCKey key,
			AlgorithmID id) {
		try {
			Encrypt0Message encrypt0Message = new Encrypt0Message();
			encrypt0Message.SetContent(plaintext.toBytes());

			encrypt0Message.addAttribute(HeaderKeys.Algorithm, id.AsCBOR(), Attribute.PROTECTED);

			encrypt0Message.encrypt(key.key);
			encrypt0Message.SetContent((byte[]) null);

			// byte[] encrypted = encrypt0Message.getEncryptedContent();

			return SCCCiphertext.createFromExistingCiphertext(encrypt0Message.EncodeToBytes());

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

}
