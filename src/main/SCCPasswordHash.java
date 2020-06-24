package main;

import java.util.Base64;

import com.upokecenter.cbor.CBORObject;

import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.PasswordHashMessage;

public class SCCPasswordHash extends AbstractSCCPasswordHash {

	byte[] hashMsg;
	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public SCCPasswordHash(byte[] hashMsg) {
		this.hashMsg = hashMsg;
	}

	@Override
	public boolean verifyHash(PlaintextContainer password) {
		try {
			return scc.verifyPassword(password, this);
		} catch (CoseException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public byte[] getMessageBytes() {
		return this.hashMsg;
	}

	@Override
	public CBORObject getAlgorithmIdentifier() {
		PasswordHashMessage msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		return obj;
	}

	@Override
	public String getPlain() {
		PasswordHashMessage m = convertByteToMsg();
		return Base64.getEncoder().encodeToString(m.GetContent());
	}

	@Override
	public PlaintextContainer getHashedContent() {
		try {
			PasswordHashMessage m = convertByteToMsg();
			return new PlaintextContainer(Base64.getEncoder().encodeToString(m.getHashedContent()));

		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}

	@Override
	public PasswordHashMessage convertByteToMsg() {
		try {
			return (PasswordHashMessage) PasswordHashMessage.DecodeFromBytes(this.hashMsg);
		} catch (CoseException e) {
			e.printStackTrace();
			return null;
		}
	}
}
