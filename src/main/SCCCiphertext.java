package main;

import java.nio.charset.Charset;
import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.Message;

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
	

	
	/*
	protected Message convertByteToMsg() {
		try {
			return (Message) Message.DecodeFromBytes(this.msg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
	

	protected AlgorithmID getAlgorithmIdentifier() {
		try {
		Message msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(obj);
		return alg;
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	
	}

	
	protected byte[] getCiphertextBytes() {
		return this.ciphertext;
	}*/

}
