package main;

import java.nio.charset.Charset;
import COSE.CoseException;

public class PlaintextContainer implements PlaintextContainerInterface {

	private byte[] plaintext;
	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public PlaintextContainer(byte[] plaintext) {
		this.plaintext = plaintext;
	}
	

	@Override
	public byte[] getPlaintextBytes() {
		return plaintext;
	}

	
	@Override
	public String getPlaintextAsString(Charset c) {
		return new String(this.plaintext, c);

	}

	@Override
	public boolean validateHash(AbstractSCCHash hash) {
		try {
			return scc.validateHash(this, hash);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}


	@Override
	public boolean validatePasswordHash(AbstractSCCPasswordHash passwordHash) {
		try {
			return scc.validatePasswordHash(this, passwordHash);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}


	@Override
	public SCCCiphertext symmetricEncrypt(AbstractSCCKey key) {
		try {
			return scc.symmetricEncrypt(key, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCCiphertext asymmetricEncrypt(AbstractSCCKeyPair keyPair) {
		try {
			return scc.asymmetricEncrypt(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCSignature sign(AbstractSCCKeyPair keyPair) {
		try {
			return scc.sign(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCHash hash() {
		try {
			return scc.hash(this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


	@Override
	public SCCPasswordHash passwordHash() {
		try {
			return scc.passwordHash(this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}


}
