package main;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
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

public class SecureCryptoConfig implements SecureCryptoConfigInterface {

	protected static String sccFileName;

	// TODO refactor in separate class?
	static enum AlgorithmIDEnum {
		// symmetric:
		// Algo_Mode_key_IV
		AES_GCM_256_96, AES_GCM_128_96,
		// Digital Signature
		ECDSA_512,
		// Hash
		SHA_512,
		// asymmetric:
		RSA_SHA_256,
		// PasswordHash
		PBKDF_SHA_256
	}

	public SecureCryptoConfig() {
		SecureCryptoConfig.sccFileName = JSONReader.getLatestSCC(5);
	}

	public SecureCryptoConfig(String sccFileName) {
		SecureCryptoConfig.sccFileName = sccFileName;
	}

	public SecureCryptoConfig(int securityLevel) {
		SecureCryptoConfig.sccFileName = JSONReader.getLatestSCC(securityLevel);
	}

	public String getSccFile() {
		return SecureCryptoConfig.sccFileName;
	}

	protected static HashSet<String> getEnums() {
		HashSet<String> values = new HashSet<String>();

		for (AlgorithmIDEnum c : AlgorithmIDEnum.values()) {
			values.add(c.name());
		}

		return values;
	}

	@Override
	public SCCCiphertext symmetricEncrypt(AbstractSCCKey key, PlaintextContainerInterface plaintext)
			throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption,
				".\\src\\main\\" + SecureCryptoConfig.sccFileName);

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

	
	
	
	@Override
	public SCCCiphertext symmetricReEncrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext) throws CoseException {

		PlaintextContainer decrypted = symmetricDecrypt(key, ciphertext);
		return symmetricEncrypt(key, decrypted);
	}


	@Override
	public SCCCiphertext fileEncrypt(AbstractSCCKey key, String filepath) throws NoSuchAlgorithmException {
		
		ArrayList<String> algorithms = new ArrayList<String>();
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption,
				".\\src\\main\\" + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case AES_GCM_256_96:
					return UseCases.fileEncryptWithParams(key, filepath, AlgorithmID.AES_GCM_256);
				case AES_GCM_128_96:
					return UseCases.fileEncryptWithParams(key, filepath, AlgorithmID.AES_GCM_256);
				default:
					break;

				}
			}

		}
		throw new NoSuchAlgorithmException();
	}
	
	@Override
	public PlaintextContainer fileDecrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext, String filepath) {
		try {
			Encrypt0Message msg = (Encrypt0Message) Encrypt0Message.DecodeFromBytes(ciphertext.msg);
			// Encrypt0Message msg = sccciphertext.msg;
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



	@Override
	public SCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair, PlaintextContainerInterface plaintext)
			throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();
		algorithms = JSONReader.getAlgos(CryptoUseCase.AsymmetricEncryption,
				".\\src\\main\\" + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {

			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case RSA_SHA_256:
					return UseCases.createAsymMessage(plaintext, AlgorithmID.RSA_OAEP_SHA_256, keyPair);
				default:
					break;
				}
			}

		}
		throw new CoseException("No supported algorithm!");
	}

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

	@Override
	public SCCCiphertext asymmetricReEncrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
			throws CoseException {
		PlaintextContainer decrypted = asymmetricDecrypt(keyPair, ciphertext);
		return asymmetricEncrypt(keyPair, decrypted);
	}

	@Override
	public SCCHash hash(PlaintextContainerInterface plaintext) throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();
		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.Hashing, ".\\src\\main\\" + SecureCryptoConfig.sccFileName);

		for (int i = 0; i < algorithms.size(); i++) {
			// get first one, later look what to do if first is not validate -> take next
			String sccalgorithmID = algorithms.get(i);

			// TODO mapping from sting to enum:

			if (getEnums().contains(sccalgorithmID)) {

				AlgorithmIDEnum chosenAlgorithmID = AlgorithmIDEnum.valueOf(sccalgorithmID);

				switch (chosenAlgorithmID) {
				case SHA_512:
					PlaintextContainer p = new PlaintextContainer(plaintext.getByteArray());
					return UseCases.createHashMessage(p, AlgorithmID.SHA_512);
				default:
					break;
				}
			}

		}
		throw new CoseException("No supported algorithm!");
	}

	// Hash again
	@Override
	public AbstractSCCHash updateHash(PlaintextContainerInterface plaintext) throws CoseException {
		return hash(plaintext);
	}

	// Hash same plain two times and look if it is the same
	@Override
	public boolean validateHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException {
		String s = hash.getHashedContent().getBase64();

		SCCHash hash1 = hash(plaintext);
		String s1 = hash1.getHashedContent().getBase64();


		return s.equals(s1);
	}

	@Override
	public SCCSignature sign(AbstractSCCKeyPair k, PlaintextContainerInterface plaintext) throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();
		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.Signing, ".\\src\\main\\" + SecureCryptoConfig.sccFileName);

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

	// Sign again?
	@Override
	public SCCSignature updateSignature(AbstractSCCKeyPair key, PlaintextContainerInterface plaintext) throws CoseException {
		return sign(key, plaintext);
	}

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

	@Override
	public SCCPasswordHash passwordHash(PlaintextContainerInterface password) throws CoseException {

		ArrayList<String> algorithms = new ArrayList<String>();
		// read our Algorithms for symmetric encryption out of JSON
		algorithms = JSONReader.getAlgos(CryptoUseCase.PasswordHashing,
				".\\src\\main\\" + SecureCryptoConfig.sccFileName);

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

	@Override
	public SCCCiphertextOutputStream streamEncrypt(AbstractSCCKey key, InputStream inputStream) throws NoSuchAlgorithmException {

		ArrayList<String> algorithms = new ArrayList<String>();
		algorithms = JSONReader.getAlgos(CryptoUseCase.SymmetricEncryption,
				".\\src\\main\\" + SecureCryptoConfig.sccFileName);

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
	@Override
	public PlaintextOutputStream streamDecrypt(AbstractSCCKey key, AbstractSCCCiphertextOutputStream ciphertext, InputStream inputStream) {
		try {
			
			Cipher cipher = Cipher.getInstance(ciphertext.param.algo);
			GCMParameterSpec spec = new GCMParameterSpec(ciphertext.param.tagLength, ciphertext.param.nonce);
			cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), spec);


			PlaintextOutputStream plaintextStream = new PlaintextOutputStream(inputStream, cipher);
			return plaintextStream;
			
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {

			e.printStackTrace();
		}
		return null;
	}
	**/

}

