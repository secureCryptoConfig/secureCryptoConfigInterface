package main;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.Message;

public class SCCCiphertext extends AbstractSCCCiphertext {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	// for COSE
	public SCCCiphertext(PlaintextContainerInterface plaintext, byte[] cipher, AbstractSCCKey keyPair, byte[] msg) {
		super(plaintext, cipher, keyPair, msg);
	}
	
	public SCCCiphertext(PlaintextContainerInterface plain, byte[] cipher, AbstractSCCKeyPair keyPair, byte[] msg) {
		super(plain, cipher, keyPair, msg);
	}

	@Override
	public byte[] getMessageBytes() {
		return this.msg;
	}

	@Override
	public AlgorithmID getAlgorithmIdentifier() throws CoseException {
		Message msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(obj);
		return alg;
	}

	@Override
	public byte[] getCipherBytes() {
		return this.cipher;
	}

	@Override
	public Message convertByteToMsg() {
		try {
			return (Message) Message.DecodeFromBytes(this.msg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public PlaintextContainerInterface getPlain() {
		return this.plain;
	}


	@Override
	public PlaintextContainer symmetricDecrypt(SCCKey key) {
		try {
			return scc.symmetricDecrypt(key, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public PlaintextContainer asymmetricDecrypt(SCCKeyPair keyPair) {
		try {
			return scc.asymmetricDecrypt(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

}
