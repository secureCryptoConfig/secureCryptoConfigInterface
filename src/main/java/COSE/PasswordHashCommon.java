package COSE;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public abstract class PasswordHashCommon extends Message {

	protected String contextString;
	protected byte[] rgbHashed;
	// protected byte[] salt;

	byte[] computePasswordHash(byte[] rgbToBeHashed) throws CoseException {
		AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
		return computePasswordHash(alg, rgbToBeHashed);
	}

	byte[] computePasswordHash(AlgorithmID alg, byte[] rgbToBeHashed) throws CoseException {
		String algName = null;
		int saltLength, iterations = 0;

		switch (alg) {
		case PBKDF_SHA_512:
			saltLength = 64;
			iterations = 10000;
			algName = "PBKDF2WithHmacSHA512";
			return pbkdf(rgbToBeHashed, alg, saltLength, iterations, algName);
		case PBKDF_SHA_256:
			saltLength = 64;
			iterations = 10000;
			algName = "PBKDF2WithHmacSHA256";
			return pbkdf(rgbToBeHashed, alg, saltLength, iterations, algName);
		case SHA_512_64:
			saltLength = 64;
			iterations = 10000;
			algName = "SHA-512";
			return hash(rgbToBeHashed, alg, saltLength, iterations, algName);
		default:
			throw new CoseException("Unsupported Algorithm Specified");
		}

	}

	private byte[] hash(byte[] rgbToBeHashed, AlgorithmID alg, int saltLength, int iterations, String algName)
			throws CoseException {

		try {
			salt = generateRandomByteArray(saltLength);
			MessageDigest md = MessageDigest.getInstance("SHA-512");

			md.update(salt);
			rgbHashed = md.digest(rgbToBeHashed);
			return rgbHashed;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	private byte[] pbkdf(byte[] rgbToBeHashed, AlgorithmID alg, int saltLength, int iterations, String algName)
			throws CoseException {
		try {
			salt = generateRandomByteArray(saltLength);
			String content = new String(rgbToBeHashed, StandardCharsets.UTF_8);
			char[] charContent = content.toCharArray();
			KeySpec spec = new PBEKeySpec(charContent, salt, iterations, alg.getKeySize());
			SecretKeyFactory factory = SecretKeyFactory.getInstance(algName);
			rgbHashed = factory.generateSecret(spec).getEncoded();
			return rgbHashed;

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			throw new CoseException("No supported algorithm!");
		}
	}

	public byte[] getHashedContent() throws CoseException {

		return rgbHashed;
	}

	public byte[] getSalt() throws CoseException {

		return salt;
	}

	public static byte[] generateRandomByteArray(int length) {
		try {
			// GENERATE random nonce (number used once)
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

	byte[] computePasswordHashWithSalt(byte[] rgbToBeHashed, byte[] salt) throws CoseException {
		AlgorithmID alg = AlgorithmID.FromCBOR(findAttribute(HeaderKeys.Algorithm));
		return computePasswordHashWithAlg(alg, rgbToBeHashed, salt);
	}

	private byte[] computePasswordHashWithAlg(AlgorithmID alg, byte[] rgbToBeHashed, byte[] salt) throws CoseException {
		String algName = null;
		int iterations = 0;

		switch (alg) {
		case PBKDF_SHA_512:
			iterations = 10000;
			algName = "PBKDF2WithHmacSHA512";
			return pbkdfWithSalt(alg, rgbToBeHashed, salt, iterations, algName);
		case PBKDF_SHA_256:
			iterations = 10000;
			algName = "PBKDF2WithHmacSHA256";
			return pbkdfWithSalt(alg, rgbToBeHashed, salt, iterations, algName);
		case SHA_512_64:
			iterations = 10000;
			algName = "SHA-512";
			return hashWithSalt(alg, rgbToBeHashed, salt, iterations, algName);
		default:
			throw new CoseException("Unsupported Algorithm Specified");
		}

	}

	private byte[] pbkdfWithSalt(AlgorithmID alg, byte[] rgbToBeHashed, byte[] salt, int iterations, String algName)
			throws CoseException {
		try {
			String content = new String(rgbToBeHashed, StandardCharsets.UTF_8);
			char[] charContent = content.toCharArray();
			KeySpec spec = new PBEKeySpec(charContent, salt, iterations, alg.getKeySize());
			SecretKeyFactory factory = SecretKeyFactory.getInstance(algName);
			rgbHashed = factory.generateSecret(spec).getEncoded();
			return rgbHashed;

		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
			throw new CoseException("No supported algorithm!");
		}
	}

	private byte[] hashWithSalt(AlgorithmID alg, byte[] rgbToBeHashed, byte[] salt, int iterations, String algName)
			throws CoseException {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");

			md.update(salt);
			rgbHashed = md.digest(rgbToBeHashed);
			return rgbHashed;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

}
