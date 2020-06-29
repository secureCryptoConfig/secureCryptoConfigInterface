package main;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class SCCKeyPair extends AbstractSCCKeyPair {
	
	public enum keyPairUseCase{
		AsymmetricEncryption, Signing
	}

	public SCCKeyPair(KeyPair pair) {
		super(pair);
	}

	@Override
	public PublicKey getPublic() {
		return this.pair.getPublic();
	}
	
	@Override
	public PrivateKey getPrivate() {
		return this.pair.getPrivate();
	}
	

	@Override
	public KeyPair getKeyPair() {
		return this.pair;
	}

}
