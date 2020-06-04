package main;

public class KeyGeneration extends SCCKey{

	private static final long serialVersionUID = 1L;
	byte[] key;
	String algorithm;
	
	public KeyGeneration(byte[] key, String algorithm)
	{
		super(key, algorithm);
		
	}

	@Override
	SCCKey createKey(byte[] bytes) {
		return null;
	}

	@Override
	SCCKeyType getSCCKeyType() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	String getDefaultAlgorithm() {
		// TODO Auto-generated method stub
		return null;
	}
	

}
