package main;

import java.util.Base64;

public class SCCHash extends AbstractSCCHash{

	byte[] hash;
	
	@Override
	boolean verify(PlaintextContainer plaintext) {
		// TODO Auto-generated method stub
		return false;
	}

	public SCCHash(byte[] hash)
	{
		this.hash = hash;
	}

	@Override
	public String toString() {
		return Base64.getEncoder().encodeToString(this.hash);
	}
}
