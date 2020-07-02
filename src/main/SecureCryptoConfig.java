package main;

import java.io.FileOutputStream;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
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

/**
 * Class with main functionality. Implements the SecureCryptoConfigInterface.
 * @author Lisa
 *
 */
public class SecureCryptoConfig implements SecureCryptoConfigInterface {

	protected static String sccFileName = JSONReader.getLatestSCC(SecurityLevel.SecurityLevel_5);

	//Contains all considered Security Level numbers
	public static enum SecurityLevel {
		SecurityLevel_1, SecurityLevel_2, SecurityLevel_3, SecurityLevel_4, SecurityLevel_5
	}

	//All supported algorithm names
	protected static enum AlgorithmIDEnum {
		// symmetric:
		// Algo_Mode_key_IV
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
	 * Set a specific SCCFilename that should be used
	 * @param sccFileNameNew
	 */
	public void setSCCFile(String sccFileNameNew) {
		sccFileName = sccFileNameNew;
	}

	/**
	 * Set the latest SCC file of a specific Security level for usage
	 * @param level
	 */
	public static void setSecurityLevel(SecurityLevel level) {
		sccFileName = JSONReader.getLatestSCC(level);
	}

	/**
	 * Return the name of the SCC file that is currently used
	 * @return
	 */
	public static String getSccFile() {
		return SecureCryptoConfig.sccFileName;
	}

	/**
	 * Put all values from AlgorithmIDEnum in a Set 
	 * @return
	 */
	protected static HashSet<String> getEnums() {
		HashSet<String> values = new HashSet<String>();

		for (AlgorithmIDEnum c : AlgorithmIDEnum.values()) {
			values.add(c.name());
		}

		return values;
	}

	/**
	 * Symmetric encryption with a certain key for a given plaintext.
	 */
	@Override
	public SCCCiphertext symmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();

		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption, JSONReader.basePath + SecureCryptoConfig.sccFileName);
		for (int i = 0; i < algorithms.size(); i++) {

			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

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
		throw new CoseException("No supported algorithms!");
	}
	
	/**
	 * Symmetric encryption with a certain key for a given byte[] plaintext.
	 */
	@Override
	public SCCCiphertext symmetricEncrypt(AbstractSCCKey key, byte[] plaintext) throws CoseException {
		try {
			return symmetricEncrypt(key, new PlaintextContainer(plaintext));
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Decryption of a given ciphertext.
	 */
	@Override
	public PlaintextContainer symmetricDecrypt(AbstractSCCKey key, AbstractSCCCiphertext sccciphertext)
			throws CoseException {
		try {
			Encrypt0Message msg = (Encrypt0Message) Encrypt0Message.DecodeFromBytes(sccciphertext.msg);
			return new PlaintextContainer(msg.decrypt(key.getByteArray()));
		} catch (CoseException e) {
			e.printStackTrace();
			throw new CoseException("No supported algorithm!");
		}
	}

	/**
	 * ReEncrypts a given ciphertext. Ciphertext will be first decrypted and than decrypted with the current SCC again.
	 */
	@Override
	public SCCCiphertext symmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext) throws CoseException {

		PlaintextContainer decrypted = symmetricDecrypt(key, ciphertext);
		return symmetricEncrypt(key, decrypted);
	}

	/**
	 * Encryption of content of a given file. Ciphertext will overwrite the file content.
	 */
	@Override
	public SCCCiphertext fileEncrypt(AbstractSCCKey key, String filepath) throws NoSuchAlgorithmException {

		ArrayList<String> algorithms = new ArrayList<String>();
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption, JSONReader.basePath + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_96:
					if (key.getByteArray().length < 32) {
						throw new SecurityException("Key has not the correct size. At least 256 bit are needed!");
					}
					return UseCases.fileEncryptWithParams(key, filepath, AlgorithmID.AES_GCM_256);
				case AES_GCM_128_96:
					if (key.getByteArray().length < 16) {
						throw new SecurityException("Key has not the correct size. At least 256 bit are needed!");
					}
					return UseCases.fileEncryptWithParams(key, filepath, AlgorithmID.AES_GCM_256);
				default:
					break;

				}
			}

		}
		throw new NoSuchAlgorithmException();
	}

	/**
	 * Decryption of a ciphertext contained in a given file. Decrypted content will over write the existing file content.
	 */
	@Override
	public PlaintextContainer fileDecrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext, String filepath) {
		try {
			Encrypt0Message msg = (Encrypt0Message) Encrypt0Message.DecodeFromBytes(ciphertext.msg);
			byte[] decrypted = msg.decrypt(key.getByteArray());
			PlaintextContainer p = new PlaintextContainer(decrypted);

			FileOutputStream fileOutputStream = new FileOutputStream(filepath);
			fileOutputStream.write(decrypted);

			fileOutputStream.close();

			return p;
		} catch (IOException | CoseException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Asymmetric encryption with a certain key for a given plaintext.
	 */
	@Override
	public SCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext)
			throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();
		algorithms = JSONReader.getAlgos(CryptoUseCase.AsymmetricEncryption, JSONReader.basePath + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

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
		throw new CoseException("No supported algorithm!");
	}

	/**
	 * Asymmetric encryption with a certain key for a given byte[] plaintext.
	 */
	@Override
	public SCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair, byte[] plaintext) throws CoseException {
		try {
			return asymmetricEncrypt(keyPair, new PlaintextContainer(plaintext));
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * Asymmetric encryption with a certain key for a given plaintext.
	 */
	@Override
	public PlaintextContainer asymmetricDecrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException {

		try {
			AsymMessage msg = (AsymMessage) AsymMessage.DecodeFromBytes(ciphertext.msg);
			return new PlaintextContainer(msg.decrypt(keyPair.getKeyPair()));
		} catch (CoseException e) {
			e.printStackTrace();

		}
		throw new CoseException("No supported algorithm!");

	}

	/**
	 * ReEncrypts a given ciphertext. Ciphertext will be first decrypted and than decrypted with the current SCC again.
	 */
	@Override
	public SCCCiphertext asymmetricReEncrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException {
		PlaintextContainer decrypted = asymmetricDecrypt(keyPair, ciphertext);
		return asymmetricEncrypt(keyPair, decrypted);
	}

	/**
	 * Hashing of a given plaintext
	 */
	@Override
	public SCCHash hash(PlaintextContainerInterface plaintext) throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();
		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.Hashing, JSONReader.basePath + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {
			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case SHA_512:
					PlaintextContainer p = new PlaintextContainer(plaintext.getPlaintextBytes());
					return UseCases.createHashMessage(p, AlgorithmID.SHA_512);
				default:
					break;
				}
			}

		}
		throw new CoseException("No supported algorithm!");
	}
	
	/**
	 * Hashing of a given byte[] plaintext
	 */
	@Override
	public SCCHash hash(byte[] plaintext) throws CoseException {
		try {
			return hash(new PlaintextContainer(plaintext));
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Given a hash of a plaintext: the corresponding plaintext will be hashed again with the current SCC.
	 */
	@Override
	public SCCHash updateHash(AbstractSCCHash hash) throws CoseException {
		return hash(hash.getPlaintextAsPlaintextContainer());
	}

	/**
	 * A given plaintext will be hashed. The resulting hash will be compared with a given hash.
	 * If identical plaintexts are hashed two times (with the same SCC) the resulting hashs are identical.
	 */
	@Override
	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException {
		String s = hash.getHashAsString(StandardCharsets.UTF_8);

		SCCHash hash1 = hash(plaintext);
		String s1 = hash1.getHashAsString(StandardCharsets.UTF_8);
		return s.equals(s1);
	}

	/**
	 * Signing of a plaintext with a specific key.
	 */
	@Override
	public SCCSignature sign(AbstractSCCKeyPair k, PlaintextContainerInterface plaintext) throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();
		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.Signing, JSONReader.basePath + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {
			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case ECDSA_512:
					return UseCases.createSignMessage(plaintext, k, AlgorithmID.ECDSA_512);
				default:
					break;
				}
			}

		}
		throw new CoseException("No supported algorithm!");
	}
	

	/**
	 * Signing of a byte[] plaintext with a specific key.
	 */
	@Override
	public SCCSignature sign(AbstractSCCKeyPair key, byte[] plaintext) throws CoseException {
		try {
			return sign(key, new PlaintextContainer(plaintext));
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	

	/**
	 * Given a signature of a plaintext: the corresponding plaintext will be signed again with the current SCC.
	 */
	@Override
	public SCCSignature updateSignature(AbstractSCCKeyPair key, AbstractSCCSignature signature) throws CoseException {
		return sign(key, signature.plaintext);
	}

	/**
	 * A given signature is checked for validity
	 */
	@Override
	public boolean validateSignature(AbstractSCCKeyPair key, AbstractSCCSignature signature) {

		try {
			Sign1Message msg = signature.convertByteToMsg();
			OneKey oneKey = new OneKey(key.getPublic(), key.getPrivate());
			return msg.validate(oneKey);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}

	}

	/**
	 * Given password will be hashed.
	 */
	@Override
	public SCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();
		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.PasswordHashing, JSONReader.basePath + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {
			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

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
	
	/**
	 * Given byte[] password will be hashed.
	 */
	@Override
	public SCCPasswordHash passwordHash(byte[] password) throws CoseException {
		try {
			return passwordHash(new PlaintextContainer(password));
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * A given password will be hashed. The resulting hash will be compared with a given hash.
	 * If identical passwords are hashed two times (with the same SCC) the resulting hashs are identical.
	 */
	@Override
	public boolean validatePasswordHash(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException {
		PasswordHashMessage msg = (PasswordHashMessage) PasswordHashMessage
				.DecodeFromBytes(passwordhash.getMessageBytes());
		CBORObject algX = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(algX);

		SCCPasswordHash hash = UseCases.createPasswordHashMessageSalt(password, alg, msg.getSalt());
		PasswordHashMessage msg1 = (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(hash.getMessageBytes());

		String hash1 = Base64.getEncoder().encodeToString(msg.getHashedContent());
		String hash2 = Base64.getEncoder().encodeToString(msg1.getHashedContent());

		return hash1.equals(hash2);

	}

	/**
	 * Encryption of content of a given Inputstream. 
	 */
	@Override
	public SCCCiphertextOutputStream streamEncrypt(AbstractSCCKey key, InputStream inputStream)
			throws NoSuchAlgorithmException {

		ArrayList<String> algorithms = new ArrayList<String>();
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption, JSONReader.basePath + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_96:
					return UseCases.fileEncryptStream(key, AlgorithmID.AES_GCM_256, inputStream);
				case AES_GCM_128_96:
					return UseCases.fileEncryptStream(key, AlgorithmID.AES_GCM_128, inputStream);

				default:
					break;

				}
			}

		}
		throw new NoSuchAlgorithmException();
	}



	/**
	 * 
	 * Decryption of content of a given Outputstream. 
	 *
	 * @Override public PlaintextOutputStream streamDecrypt(AbstractSCCKey key,
	 *           AbstractSCCCiphertextOutputStream ciphertext, InputStream
	 *           inputStream) { try {
	 * 
	 *           Cipher cipher = Cipher.getInstance(ciphertext.param.algo);
	 *           GCMParameterSpec spec = new
	 *           GCMParameterSpec(ciphertext.param.tagLength,
	 *           ciphertext.param.nonce); cipher.init(Cipher.DECRYPT_MODE,
	 *           key.getSecretKey(), spec);
	 * 
	 * 
	 *           PlaintextOutputStream plaintextStream = new
	 *           PlaintextOutputStream(inputStream, cipher); return plaintextStream;
	 * 
	 *           } catch (InvalidKeyException | InvalidAlgorithmParameterException |
	 *           NoSuchAlgorithmException | NoSuchPaddingException e) {
	 * 
	 *           e.printStackTrace(); } return null; }
	 **/


}
