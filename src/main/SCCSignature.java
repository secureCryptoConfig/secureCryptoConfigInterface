package main;

import java.util.Base64;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.Sign1Message;

public class SCCSignature extends AbstractSCCSignature{

	SecureCryptoConfig scc = new SecureCryptoConfig();
	public SCCSignature(byte[] signatureMsg) {
		super(signatureMsg);
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
	public CBORObject getAlgorithmIdentifier() {
		Sign1Message msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		return obj;
	}

	@Override
	public String getPlain() {
		Sign1Message m = convertByteToMsg();
		return Base64.getEncoder().encodeToString(m.GetContent());
	}

	@Override
	public PlaintextContainer getSignature() {
		Sign1Message m = convertByteToMsg();
		return new PlaintextContainer(m.getSignature());
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
