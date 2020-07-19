package main;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.HashSet;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.AsymMessage;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.PasswordHashMessage;
import COSE.Sign1Message;
import main.JSONReader.CryptoUseCase;
import main.SCCKey.KeyType;

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

	protected static String sccPath = JSONReader.parseFiles(JSONReader.getBasePath());
	protected static boolean customPath = false;

	/**
	 * All supported algorithm names
	 *
	 */
	protected static enum AlgorithmIDEnum {
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
			sccPath = JSONReader.getLatestSCC(level);
		} else {
			throw new IllegalArgumentException("There are no files with the specified Security Level");
		}
	}

	/**
	 * Return the name of the Secure Crypto Config file that is currently used to
	 * look up algorithms to use for executing cryptographic use case
	 * 
	 * @return SCCFilePath: path to the used Secure Crypto Config file
	 */
	public static String getUsedSCC() {
		// TODO adapt to not use the path, but the specified policyName from the file,
		// as the file path is not standards relevant.
		return sccPath;
	}

	/**
	 * Set path to a custom root folder "scc-configs" which contains the Secure
	 * Crypto Config files.
	 * 
	 * @param path: path to "scc-config" directory. Path should end with \\
	 * @throws InvalidPathException
	 */
	public static void setCustomSCCPath(Path path) {
		customPath = true;
		if (path.toFile().exists()) {
			sccPath = JSONReader.parseFiles(path.toString());
		} else {
			throw new InvalidPathException(path.toString(), "Path is not existing");
		}
	}

	/**
	 * Set Secure Crypto Config file to use
	 * 
	 * @param filePath: path to the Secure Crypto Config file to use
	 * @throws InvalidPathException
	 */
	public static void setSCCFile(String filePath) {
		// TODO usually we don't want to set a path to use but a policy to use
		File file = new File(filePath);
		if (file.exists()) {
			sccPath = filePath;
		} else {
			throw new InvalidPathException(filePath, "Path is not existing");
		}

	}

	/**
	 * Set default Secure Crypto Configuration using Secure Crypto Config files at
	 * "src/scc-configs" Only necessary if a custom path with
	 * {@link #setCustomSCCPath(String)} or {@link #setSCCFile(String)} was called
	 * before
	 */
	public static void setDefaultSCC() {
		customPath = false;
		sccPath = JSONReader.parseFiles(JSONReader.getBasePath());
	}

	/**
	 * Put all values from AlgorithmIDEnum in a Set
	 * 
	 * @return hashSet
	 */
	protected static HashSet<String> getEnums() {
		HashSet<String> values = new HashSet<String>();

		for (AlgorithmIDEnum c : AlgorithmIDEnum.values()) {
			values.add(c.name());
		}

		return values;
	}

	@Override
	public SCCCiphertext encryptSymmetric(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException, InvalidKeyException {

		if (key.getKeyType() == KeyType.Symmetric) {
			ArrayList<String> algorithms = new ArrayList<String>();

			algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption, sccPath);
			for (int i = 0; i < algorithms.size(); i++) {

				String sccalgorithmID = algorithms.get(i);

				if (getEnums().contains(sccalgorithmID)) {

					AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

					switch (chosenAlgorithmID) {
					case AES_GCM_256_96:
						return UseCases.createMessage(plaintext, key, AlgorithmID.AES_GCM_256);
					case AES_GCM_128_96:
						return UseCases.createMessage(plaintext, key, AlgorithmID.AES_GCM_128);
					default:
						break;

					}
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
			ArrayList<String> algorithms = new ArrayList<String>();
			algorithms = JSONReader.getAlgos(CryptoUseCase.AsymmetricEncryption, sccPath);

			for (int i = 0; i < algorithms.size(); i++) {

				String sccalgorithmID = algorithms.get(i);

				if (getEnums().contains(sccalgorithmID)) {

					AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

					switch (chosenAlgorithmID) {
					case RSA_SHA_512:
						return UseCases.createAsymMessage(plaintext, AlgorithmID.RSA_OAEP_SHA_512, keyPair);
					default:
						break;
					}
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

		ArrayList<String> algorithms = new ArrayList<String>();

		algorithms = JSONReader.getAlgos(CryptoUseCase.Hashing, sccPath);

		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case SHA_512:
					PlaintextContainer p = new PlaintextContainer(plaintext.toBytes());
					return UseCases.createHashMessage(p, AlgorithmID.SHA_512);
				default:
					break;
				}
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
			ArrayList<String> algorithms = new ArrayList<String>();
			algorithms = JSONReader.getAlgos(CryptoUseCase.Signing, sccPath);

			for (int i = 0; i < algorithms.size(); i++) {
				String sccalgorithmID = algorithms.get(i);

				if (getEnums().contains(sccalgorithmID)) {

					AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

					switch (chosenAlgorithmID) {
					case ECDSA_512:
						return UseCases.createSignMessage(plaintext, keyPair, AlgorithmID.ECDSA_512);
					default:
						break;
					}
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
		return validateSignature(keyPair, new SCCSignature(signature));
	}

	@Override
	public SCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();

		algorithms = JSONReader.getAlgos(CryptoUseCase.PasswordHashing, sccPath);

		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case PBKDF_SHA_256:
					return UseCases.createPasswordHashMessage(password, AlgorithmID.PBKDF_SHA_256);
				default:
					break;
				}
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

		SCCPasswordHash hash = UseCases.createPasswordHashMessageSalt(password, alg, msg.getSalt());

		String hash1 = new String(msg.getHashedContent(), StandardCharsets.UTF_8);
		String hash2 = new String(hash.convertByteToMsg().getHashedContent(), StandardCharsets.UTF_8);

		return hash1.equals(hash2);

	}

	@Override
	public boolean validatePasswordHash(byte[] password, AbstractSCCPasswordHash passwordhash) throws CoseException {
		return validatePasswordHash(new PlaintextContainer(password), passwordhash);
	}

}
