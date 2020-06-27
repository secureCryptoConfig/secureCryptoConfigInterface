package main;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.Sign1Message;

public class SCCSignature extends AbstractSCCSignature{

	SecureCryptoConfig scc = new SecureCryptoConfig();
	public SCCSignature(PlaintextContainer plaintext, PlaintextContainer signature, byte[] signatureMsg) {
		super(plaintext, signature, signatureMsg);
	}

	@Override
	public boolean validateSignature(SCCKeyPair key) {
		return scc.validateSignature(key, this);
	}

	@Override
	public byte[] getMessageBytes() {
		return this.signatureMsg;
	}

	@Override
	public AlgorithmID getAlgorithmIdentifier() throws CoseException  {
		Sign1Message msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(obj);
		return alg;
	}

	@Override
	public PlaintextContainer getPlain() {
		return (PlaintextContainer) this.plaintext;
	}

	@Override
	public PlaintextContainer getSignature() {
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

}
