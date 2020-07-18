package main;

import java.nio.charset.StandardCharsets;
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

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.OneKey;
import main.JSONReader.CryptoUseCase;
import main.SecureCryptoConfig.AlgorithmIDEnum;

/**
 * Class representing Key that is needed for symmetric/asymmetric encryption and signing
 * 
 * @author Lisa
 *
 */
public class SCCKey extends AbstractSCCKey {

	/**
	 * Type of the corresponding key
	 * Depending on the KeyType a key can only used for specific use cases:
	 * Symmetric needed for symmetric en/decryption
	 * Asymmetric needed for asymmetric en/decryption and signing
	 */
	public enum KeyType {
		Symmetric, Asymmetric
	}

	/**
	 * Different use cases for which a key can be created
	 * Different KeyUseCases lead to a SCCKey with a different {@link KeyType}
	 */
	public enum KeyUseCase {
		SymmetricEncryption, AsymmetricEncryption, Signing
	}

	/**
	 * Constructor which gets the {@link KeyType}, the byte[] representation of the key and the algorithm
	 * of its creation. This constructor is used in for SCCKeys of {@link KeyType#Symmetric}.
	 * If a new SCCKey should be created call {@link #createKey(KeyUseCase)}.
	 * 
	 * @param type: choice of {@link KeyType}
	 * @param key: byte[] representation of key
	 * @param algorithm: used for key creation
	 */
	public SCCKey(KeyType type, byte[] key, String algorithm) {
		super(type, key, algorithm);
	}
	

	@Override
	public KeyType getKeyType() {
		return this.type;
	}

	@Override
	public String getAlgorithm() {
		return this.algorithm;
	}

	/**
	 * Constructor which gets the {@link KeyType}, the byte[] representation of the public and private key and the algorithm
	 * of its creation. This constructor is used in for SCCKeys of {@link KeyType#Asymmetric}.
	 * If a new SCCKey should be created call {@link #createKey(KeyUseCase)}.
	 * 
	 * @param type: choice of {@link KeyType}
	 * @param publicKey: byte[] representation of public key
	 *  @param privateKey: byte[] representation of private key
	 * @param algorithm: used for key creation
	 */
	public SCCKey(KeyType type, byte[] publicKey, byte[] privateKey, String algorithm) {
		super(type, publicKey, privateKey, algorithm);
	}

	@Override
	public byte[] toBytes() {
		if (this.type == KeyType.Symmetric) {
			return this.key;
		} else {
			return null;
		}
	}

	
	@Override
	public byte[] getPublicKeyBytes() {
		if (type == KeyType.Asymmetric) {
			return this.publicKey;
		} else {
			return null;
		}
	}

	
	@Override
	public byte[] getPrivateKeyBytes() {
		if (type == KeyType.Asymmetric) {
			return this.privateKey;
		} else {
			return null;
		}
	}

	/**
	 * Returns byte[] representation of key to SecretKey for further processing
	 * @return SecretKey
	 */
	protected SecretKey getSecretKey() {
		if (this.type == KeyType.Symmetric) {
			return new SecretKeySpec(key, 0, key.length, this.algorithm);
		} else {
			return null;
		}
	}

	/**
	 * Returns byte[] representation of public key to PublicKey for further processing
	 * @return PublicKey
	 * @throws SCCException 
	 */
	protected PublicKey getPublicKey() throws SCCException {
		if (this.type == KeyType.Asymmetric) {
			try {
				return KeyFactory.getInstance(this.algorithm).generatePublic(new X509EncodedKeySpec(this.publicKey));
			} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
				throw new SCCException("Could not convert to PublicKey", e);
			}
		} else {
			return null;
		}
	}

	/**
	 * Returns byte[] representation of private key to PrivateKey for further processing
	 * @return PrivateKey
	 * @throws SCCException 
	 */
	protected PrivateKey getPrivateKey() throws SCCException {
		if (this.type == KeyType.Asymmetric) {
			try {
				return KeyFactory.getInstance(this.algorithm).generatePrivate(new PKCS8EncodedKeySpec(this.privateKey));
			} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
				throw new SCCException("Could not convert to PrivateKey!", e);
			}
		} else {
			return null;
		}
	}

	/**
	 * Create a key for a specific {@link KeyUseCase}.
	 * 
	 * Depending of specified {@link KeyUseCase} the resulting SCCKey can be used for: 
	 * - {@link KeyUseCase#SymmetricEncryption}: {@link SecureCryptoConfigInterface#encryptSymmetric(AbstractSCCKey, byte[])}, 
	 * {@link SecureCryptoConfigInterface#encryptSymmetric(AbstractSCCKey,PlaintextContainerInterface)}, {@link SecureCryptoConfigInterface#decryptSymmetric(AbstractSCCKey, AbstractSCCCiphertext)}, 
	 * {@link SecureCryptoConfigInterface#reEncryptSymmetric(AbstractSCCKey, AbstractSCCCiphertext)}
	 * - {@link KeyUseCase#AsymmetricEncryption}: {@link SecureCryptoConfigInterface#encryptAsymmetric(AbstractSCCKey, byte[])}, {@link SecureCryptoConfigInterface#reEncryptAsymmetric(AbstractSCCKey, AbstractSCCCiphertext)}
	 * {@link SecureCryptoConfigInterface#encryptAsymmetric(AbstractSCCKey, PlaintextContainerInterface)}, {@link SecureCryptoConfigInterface#decryptAsymmetric(AbstractSCCKey, AbstractSCCCiphertext)}
	 * - {@link KeyUseCase#Signing}: {@link SecureCryptoConfigInterface#sign(AbstractSCCKey, byte[])}, {@link SecureCryptoConfigInterface#sign(AbstractSCCKey, PlaintextContainerInterface)},
	 * {@link SecureCryptoConfigInterface#validateSignature(AbstractSCCKey, AbstractSCCSignature)}, {@link SecureCryptoConfigInterface#updateSignature(AbstractSCCKey, byte[])}, {@link SecureCryptoConfigInterface#updateSignature(AbstractSCCKey, PlaintextContainerInterface)}
	 * 
	 * Depending on the {@link KeyUseCase} the SCCKey get a different {@link KeyType}
	 * 
	 * @param useCase: for which Scenario is the key needed? Give a value of {@link KeyUseCase} 
	 * @return SCCKey: key that can be used for the specified use case
	 * @throws CoseException
	 * @throws NoSuchAlgorithmException
	 * @throws SCCException 
	 */
	public static SCCKey createKey(KeyUseCase useCase) throws CoseException, NoSuchAlgorithmException, SCCException {
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
	 * Creation of a key that can be used for {@link SecureCryptoConfigInterface#encryptSymmetric(AbstractSCCKey, byte[])}.
	 * 
	 * @return SCCKey
	 * @throws CoseException
	 * @throws SCCException 
	 */
	private static SCCKey createSymmetricKey() throws CoseException, SCCException {

		String algo = null;
		int keysize = 0;

		ArrayList<String> algorithms = new ArrayList<String>();

		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption, SecureCryptoConfig.sccPath);
		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);


			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
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

				KeyGenerator keyGen;
				try {
					keyGen = KeyGenerator.getInstance(algo.toString());
					keyGen.init(keysize);
					SecretKey key = keyGen.generateKey();
					return new SCCKey(KeyType.Symmetric, key.getEncoded(), algo);
				} catch (NoSuchAlgorithmException e) {
					throw new SCCException("Key could not be created! No algorithm specified!", e);
				}
			}

		}

		throw new CoseException("No supported algorithms! Key creation not possible!");

	}

	/**
	 * Auxiliary method for creating asymmetric SCCKey for asymmetric and signing
	 * 
	 * @param c
	 * @return SCCKeyPair
	 * @throws NoSuchAlgorithmException
	 * @throws SCCException 
	 * @throws CoseException 
	 */
	private static SCCKey createNewKeyPair(CryptoUseCase c) throws SCCException, CoseException {
		ArrayList<String> algorithms = new ArrayList<String>();

		algorithms = JSONReader.getAlgos(c, SecureCryptoConfig.sccPath);

		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {
				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				// Asymmetric
				case RSA_SHA_512:
					return createAsymmetricKey("RSA", 4096);
				// Signing
				case ECDSA_512:
					try {
						OneKey oneKey = OneKey.generateKey(AlgorithmID.ECDSA_512);
						return new SCCKey(KeyType.Asymmetric, oneKey.AsPublicKey().getEncoded(),
								oneKey.AsPrivateKey().getEncoded(), "EC");
					} catch (CoseException e) {
						throw new SCCException("Key could not be created!", e);
					}
				default:
					break;
				}
			}

		}
		throw new CoseException("Key could not be created! No algorithm specified!");
	}

	/**
	 * Auxiliary method for creating SCCKey with specific size for asymmetric
	 * encryption
	 * 
	 * @param algo
	 * @param keysize
	 * @return SCCKeyPair
	 */
	private static SCCKey createAsymmetricKey(String algo, int keysize) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algo);
			keyPairGenerator.initialize(keysize);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			SCCKey key = new SCCKey(KeyType.Asymmetric, keyPair.getPublic().getEncoded(),
					keyPair.getPrivate().getEncoded(), algo);
			return key;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Creation of key derived from a given password that can be used for symmetric
	 * encryption
	 * 
	 * @param password: as byte[]
	 * @return SCCKey
	 * @throws SCCException 
	 */
	public static SCCKey createSymmetricKeyWithPassword(byte[] password) throws SCCException {
		try {
			return createSymmetricKeyWithPassword(new PlaintextContainer(password));

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Creation of key derived from a given password that can be used for symmetric
	 * encryption.
	 * 
	 * @param password: as PlaintextContainer
	 * @return SCCKey
	 * @throws CoseException
	 * @throws SCCException 
	 */
	public static SCCKey createSymmetricKeyWithPassword(PlaintextContainer password) throws CoseException, SCCException {
		String algo = null;
		String keyAlgo = null;
		int keysize = 0, iterations = 0, saltLength = 0;

		ArrayList<String> algorithms = new ArrayList<String>();

		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption, SecureCryptoConfig.sccPath);

		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			if (SecureCryptoConfig.getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_96:
					algo = "PBKDF2WithHmacSHA512";
					keyAlgo = "AES";
					keysize = 256;
					iterations = 10000;
					saltLength = 64;
					break;
				case AES_GCM_128_96:
					algo = "PBKDF2WithHmacSHA512";
					keyAlgo = "AES";
					keysize = 128;
					iterations = 10000;
					saltLength = 64;
					break;
				default:
					break;

				}
				try {

					byte[] salt = generateRandomByteArray(saltLength);

					SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algo);
					KeySpec passwordBasedEncryptionKeySpec = new PBEKeySpec(
							password.toString(StandardCharsets.UTF_8).toCharArray(), salt, iterations, keysize);
					SecretKey secretKeyFromPBKDF2 = secretKeyFactory.generateSecret(passwordBasedEncryptionKeySpec);
					SecretKey key = new SecretKeySpec(secretKeyFromPBKDF2.getEncoded(), keyAlgo.toString());
					return new SCCKey(KeyType.Symmetric, key.getEncoded(), keyAlgo);
				} catch (NoSuchAlgorithmException e)
				{
					throw new SCCException("Key could not be created! No algorithm specified!", e);
				}catch(InvalidKeySpecException e) {
					throw new SCCException("Key could not be created!", e);
				}

			}

		}

		throw new CoseException("No supported algorithms! Key creation not possible!");

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
			e.printStackTrace();
			return null;
		}

	}

}
