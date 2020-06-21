package main;

import java.util.Base64;

public class SCCPasswordHash extends AbstractSCCPasswordHash {

	byte[] hash;
	
	public SCCPasswordHash(byte[] hash) {
		this.hash = hash;
	}

	@Override
	boolean verify(PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(this.hash);
	}
	
	@Override
	public byte[] getByteArray()
	{
		
		return this.hash;
	}

	
}
