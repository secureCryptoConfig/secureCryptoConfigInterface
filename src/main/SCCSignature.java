package main;

import java.nio.charset.Charset;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.Sign1Message;

public class SCCSignature extends AbstractSCCSignature {

	SecureCryptoConfig scc = new SecureCryptoConfig();

	public SCCSignature(PlaintextContainer plaintext, PlaintextContainer signature, byte[] signatureMsg) {
		super(plaintext, signature, signatureMsg);
	}

	@Override
	public boolean validateSignature(AbstractSCCKeyPair key) {
		return scc.validateSignature(key, this);
	}

	@Override
	public byte[] getMessageBytes() {
		return this.signatureMsg;
	}

	@Override
	public AlgorithmID getAlgorithmIdentifier() {
		try {
			Sign1Message msg = convertByteToMsg();
			CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
			AlgorithmID alg = AlgorithmID.FromCBOR(obj);
			return alg;
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public PlaintextContainer getSignatureAsPlaintextContainer() {
		return (PlaintextContainer) this.signature;
	}

	@Override
	public Sign1Message convertByteToMsg() {
		try {
			return (Sign1Message) Sign1Message.DecodeFromBytes(this.signatureMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public SCCSignature updateSignature(AbstractSCCKeyPair keyPair, SecureCryptoConfig scc) {
		try {
			return scc.updateSignature(keyPair, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	PlaintextContainerInterface getPlaintextAsPlaintextContainer() {
		return this.plaintext;
	}

	@Override
	String getPlaintextAsString(Charset c) {
		return new String(this.plaintext.getByteArray(), c);
	}

	@Override
	String getSignatureAsPlaintextContainer(Charset c) {
		return new String(this.signature.getByteArray(), c);
	}

}
