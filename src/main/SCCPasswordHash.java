package main;

import com.upokecenter.cbor.CBORObject;

import COSE.AlgorithmID;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.PasswordHashMessage;

public class SCCPasswordHash extends AbstractSCCPasswordHash {

	byte[] hashMsg;
	PlaintextContainer plaintext, hash;
	SecureCryptoConfig scc = new SecureCryptoConfig();
	
	public SCCPasswordHash(PlaintextContainer password, PlaintextContainer hash, byte[] hashMsg) {
		this.hashMsg = hashMsg;
		this.hash = hash;
		this.plaintext = password;
	}

	@Override
	public boolean validatePasswordHash(PlaintextContainer password) {
		try {
			return scc.validatePasswordHash(password, this);
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
	public AlgorithmID getAlgorithmIdentifier() throws CoseException {
		PasswordHashMessage msg = convertByteToMsg();
		CBORObject obj = msg.findAttribute(HeaderKeys.Algorithm);
		AlgorithmID alg = AlgorithmID.FromCBOR(obj);
		return alg;
	}

	@Override
	public PlaintextContainer getPlain() {
		
		return this.plaintext;
	}

	@Override
	public PlaintextContainer getHashedContent() {
		return this.hash;
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
