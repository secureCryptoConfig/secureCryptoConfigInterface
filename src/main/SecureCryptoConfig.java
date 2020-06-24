package main;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.AsymMessage;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HashMessage;
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
		System.out.println(sccFileName);
	}

	public SecureCryptoConfig(int securityLevel) {
		SecureCryptoConfig.sccFileName = JSONReader.getLatestSCC(securityLevel);
		System.out.println(sccFileName);
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
					return UseCases.createMessage(plaintext.getPlain(), key.key, AlgorithmID.AES_GCM_256);
				case AES_GCM_128_96:
					return UseCases.createMessage(plaintext.getPlain(), key.key, AlgorithmID.AES_GCM_128);
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
			String s = new String(msg.decrypt(key.key.getEncoded()), StandardCharsets.UTF_8);
			return new PlaintextContainer(s);
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
	public AbstractSCCCiphertext[] encrypt(AbstractSCCKey[] key, PlaintextContainerInterface plaintext) {
		
		return null;
	}

	@Override
	public SCCCiphertext fileEncrypt(AbstractSCCKey key, String filepath) throws NoSuchAlgorithmException {
		int nonceLength, tagLength;
		String algo;

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
					nonceLength = 16;
					tagLength = 128;
					algo = "AES/GCM/NoPadding";
					return UseCases.fileEncryptWithParams(key, filepath, nonceLength, tagLength, algo);
				case AES_GCM_128_96:
					nonceLength = 32;
					tagLength = 128;
					algo = "AES/GCM/NoPadding";
					return UseCases.fileEncryptWithParams(key, filepath, nonceLength, tagLength, algo);

				default:
					break;

				}
			}

		}
		throw new NoSuchAlgorithmException();
	}

	@Override
	public PlaintextContainer fileDecrypt(AbstractSCCKey key, AbstractSCCCiphertext ciphertext, String filepath) {
		String decryptedCipherText;
		try {

			Cipher cipher = Cipher.getInstance(ciphertext.parameters.algo);
			GCMParameterSpec spec = new GCMParameterSpec(ciphertext.parameters.tagLength, ciphertext.parameters.nonce);
			cipher.init(Cipher.DECRYPT_MODE, key.key, spec);

			FileInputStream fileInputStream = new FileInputStream(filepath);
			CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

			byte[] buffer = new byte[8192];
			int nread;
			while ((nread = cipherInputStream.read(buffer)) > 0) {
				byteArrayOutputStream.write(buffer, 0, nread);
			}
			FileOutputStream fileOutputStream = new FileOutputStream(filepath);
			fileOutputStream.write(buffer);

			fileOutputStream.close();
			byteArrayOutputStream.flush();
			cipherInputStream.close();

			decryptedCipherText = new String(byteArrayOutputStream.toByteArray(), StandardCharsets.UTF_8);

			PlaintextContainer p = new PlaintextContainer(decryptedCipherText);
			return p;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | IOException | InvalidKeyException
				| InvalidAlgorithmParameterException e) {

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
			String s = new String(msg.decrypt(keyPair.pair), StandardCharsets.UTF_8);
			return new PlaintextContainer(s);
		} catch (CoseException e) {
			e.printStackTrace();

		}
		throw new CoseException("No supported algorithm!");

	}

	@Override
	public AbstractSCCCiphertext asymmetricReEncrypt(AbstractSCCKeyPair keyPair, AbstractSCCCiphertext ciphertext)
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
					return UseCases.createHashMessage(plaintext.getPlain(), AlgorithmID.SHA_512);
				default:
					break;
				}
			}

		}
		throw new CoseException("No supported algorithm!");
	}

	// Einfach nochmal hashen?
	@Override
	public AbstractSCCHash reHash(PlaintextContainerInterface plaintext) throws CoseException {
		return hash(plaintext);
	}

	// Hash same plain two times and look if it is the same?
	@Override
	public boolean verifyHash(PlaintextContainerInterface plaintext, AbstractSCCHash hash) throws CoseException {
		HashMessage msg = (HashMessage) HashMessage.DecodeFromBytes(hash.getByteArray());
		String s = new String(msg.getHashedContent(), StandardCharsets.UTF_8);

		SCCHash hash1 = hash(plaintext);
		HashMessage msg1 = (HashMessage) HashMessage.DecodeFromBytes(hash1.getByteArray());
		String s1 = new String(msg1.getHashedContent(), StandardCharsets.UTF_8);

		return s.equals(s1);
	}

	@Override
	public SCCSignature sign(OneKey k, PlaintextContainerInterface plaintext) throws CoseException {

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
	public AbstractSCCSignature reSign(OneKey key, PlaintextContainerInterface plaintext) throws CoseException {
		return sign(key, plaintext);
	}

	@Override
	public boolean validateSignature(OneKey key, AbstractSCCSignature signature) {

		try {
			Sign1Message msg = (Sign1Message) Sign1Message.DecodeFromBytes(signature.signatureMsg);
			return msg.validate(key);

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
					return UseCases.createPasswordHashMessage(password.getPlain(), AlgorithmID.PBKDF_SHA_256);
				default:
					break;
				}
			}

		}
		throw new CoseException("No supported algorithm!");

	}

	@Override
	public boolean verifyPassword(PlaintextContainerInterface password, AbstractSCCPasswordHash passwordhash)
			throws CoseException {
		PasswordHashMessage msg = (PasswordHashMessage) PasswordHashMessage
				.DecodeFromBytes(passwordhash.getByteArray());
		CBORObject algX = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(algX);

		SCCPasswordHash hash = UseCases.createPasswordHashMessageSalt(password.getPlain(), alg, msg.getSalt());
		PasswordHashMessage msg1 = (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(hash.getByteArray());

		String hash1 = Base64.getEncoder().encodeToString(msg.getHashedContent());
		String hash2 = Base64.getEncoder().encodeToString(msg1.getHashedContent());

		return hash1.equals(hash2);

	}

	@Override
	public SCCCiphertextOutputStream streamEncrypt(AbstractSCCKey key, OutputStream outputstream) throws NoSuchAlgorithmException {
		int nonceLength, tagLength;
		String algo;

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
					nonceLength = 16;
					tagLength = 128;
					algo = "AES/GCM/NoPadding";
					return UseCases.fileEncryptStream(key, outputstream, nonceLength, tagLength, algo);
				case AES_GCM_128_96:
					nonceLength = 32;
					tagLength = 128;
					algo = "AES/GCM/NoPadding";
					return UseCases.fileEncryptStream(key, outputstream, nonceLength, tagLength, algo);

				default:
					break;

				}
			}

		}
		throw new NoSuchAlgorithmException();
	}

	@Override
	public AbstractSCCCiphertextOutputStream streamReEncrypt(AbstractSCCKey key, AbstractSCCCiphertextOutputStream ciphertext) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public PlaintextOutputStream streamDecrypt(AbstractSCCKey key, AbstractSCCCiphertextOutputStream ciphertext, InputStream inputStream) {
		try {
			
			Cipher cipher = Cipher.getInstance(ciphertext.param.algo);
			GCMParameterSpec spec = new GCMParameterSpec(ciphertext.param.tagLength, ciphertext.param.nonce);
			cipher.init(Cipher.DECRYPT_MODE, key.key, spec);


			PlaintextOutputStream plaintextStream = new PlaintextOutputStream(inputStream, cipher);
			return plaintextStream;
			
		} catch (InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {

			e.printStackTrace();
		}
		return null;
	}

}
