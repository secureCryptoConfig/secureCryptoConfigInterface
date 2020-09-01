package org.securecryptoconfig;

import org.securecryptoconfig.SCCKey.KeyType;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 *  @TODO <b>! Still work in progress!</b>
	 * <br><br>
 * Class needed to be able to represent the SCCKey object as byte[].
 * 
 * @author Lisa
 *
 */
@JsonAutoDetect(fieldVisibility = Visibility.ANY)
public class SCCInstanceKey {
	private KeyType type;
	private byte[] publicKey; 
	private byte[] privateKey;
	private String algorithm;
	

	private SCCInstanceKey(KeyType type, byte[] publicKey, byte[] privateKey, String algorithm){
			this.type = type;
			this.publicKey = publicKey;
			this.privateKey = privateKey;
			this.algorithm = algorithm;
		}

	private SCCInstanceKey()
		{}

	protected static byte[] createSCCInstanceKey(KeyType type, byte[] publicKey, byte[] privateKey, String algorithm)
			throws JsonProcessingException {
		ObjectMapper mapper = new ObjectMapper();

		return mapper.writeValueAsBytes(
				new SCCInstanceKey(type, publicKey, privateKey, algorithm));
	}

	public KeyType getType() {
		return type;
	}

	public void setType(KeyType type) {
		this.type = type;
	}

	public byte[] getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(byte[] publicKey) {
		this.publicKey = publicKey;
	}

	public byte[] getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(byte[] privateKey) {
		this.privateKey = privateKey;
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}

}
