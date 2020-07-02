package main;

import java.nio.charset.Charset;
import COSE.CoseException;

public class SCCCiphertext extends AbstractSCCCiphertext {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public SCCCiphertext(byte[] msg) {
		super(msg);
	}
	
	@Override
	public byte[] toBytes() {
		return this.msg;
	}
	
	@Override
	public String toString(Charset c) {
		return new String (this.msg, c);
	}
	

	@Override
	public PlaintextContainer decryptSymmetric(AbstractSCCKey key) {
		try {
			return scc.decryptSymmetric(key, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public PlaintextContainer decryptAsymmetric(AbstractSCCKeyPair keyPair) {
		try {
			return scc.decryptAsymmetric(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public SCCCiphertext reEncryptSymmetric(AbstractSCCKey key)  {
		try {
		return scc.reEncryptSymmetric(key, this);
		}catch(CoseException e)
		{
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public SCCCiphertext reEncryptAsymmetric(AbstractSCCKeyPair keyPair) {
		try {
			return scc.reEncryptAsymmetric(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
	

}
