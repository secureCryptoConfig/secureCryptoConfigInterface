package main;

import java.util.Base64;

import com.upokecenter.cbor.CBORObject;

import COSE.AsymMessage;
import COSE.CoseException;
import COSE.Encrypt0Message;
import COSE.HeaderKeys;
import COSE.Message;

public class SCCCiphertext extends AbstractSCCCiphertext {

	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	// for COSE
	public SCCCiphertext(byte[] msg) {
		super(msg);
	}

	@Override
	public byte[] getMessageBytes() {
		return this.msg;
	}

	@Override
	public CBORObject getAlgorithmIdentifier() {
		Message msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		return obj;
	}

	@Override
	public PlaintextContainer getSymmetricCipher() {
		try {
			AsymMessage m = (AsymMessage) AsymMessage.DecodeFromBytes(this.msg);
			return new PlaintextContainer(Base64.getEncoder().encodeToString(m.getEncryptedContent()));

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}

	}

	@Override
	public PlaintextContainer getAsymmetricCipher() {
		try {
			Encrypt0Message m = (Encrypt0Message) Encrypt0Message.DecodeFromBytes(this.msg);
			return new PlaintextContainer(Base64.getEncoder().encodeToString(m.getEncryptedContent()));

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	private Message convertByteToMsg() {
		try {
			return (Message) Message.DecodeFromBytes(this.msg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public String getPlain() {
		Message m = convertByteToMsg();
		return Base64.getEncoder().encodeToString(m.GetContent());
	}

	// Only necessary for file encrypt (no COSE support)
	public SCCCiphertext(byte[] ciphertext, AbstractSCCAlgorithmParameters parameters) {
		super(ciphertext, parameters);
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
