package main;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;

import COSE.CoseException;


public class Server {
	public static ArrayList<Integer> usedClientID = new ArrayList<Integer>();
	protected static HashMap<Integer, PublicKey> clients = new HashMap<Integer, PublicKey>();
	final static String masterPassword = "Confidential";
	
	//create a not existing id
	private static int generateID(PublicKey publicKey)
	{
		for (int i = 1; i < 100; i++) {
			if(!usedClientID.contains(i))
			{
				usedClientID.add(i);
				clients.put(i, publicKey);
				return i;
			}
		}
		return 0;
	}
	
	private static void sendID()
	{
		//TODO: send ID to client
	}
	
	private void checkSignature(int clientID, byte[] order, byte[] signature) throws CoseException
	{
		PublicKey publicKey = clients.get(clientID);
		SecureCryptoConfig scc = new SecureCryptoConfig();
		
		//SCCKeyPair keyPair = new SCCKeyPair(new KeyPair(publicKey, null));
		SCCKeyPair keyPair = null;
		boolean resultValidation = scc.validateSignature(keyPair, signature);
		
		if(resultValidation == true)
		{
			encryptOrder(order);
		}
		
		//TODO: return some Info to client
	}
	
	private void encryptOrder(byte[] order) throws CoseException
	{
		SecureCryptoConfig scc = new SecureCryptoConfig();
		SCCKey key = SCCKey.createKeyWithPassword(masterPassword.getBytes());
		SCCCiphertext cipher = scc.encryptSymmetric(key, order);
		
		//TODO: store cipher as byte[] somewhere
		
	}

}
