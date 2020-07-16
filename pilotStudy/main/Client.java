package main;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import COSE.CoseException;
import main.SCCKeyPair.KeyPairUseCase;

public class Client {

	protected static HashSet<Client> clients = new HashSet<Client>();
	int clientID;
	KeyPair pair;
	
	enum TransactionType {
		Buy, Sell
	}
	
	public Client(int clientID, KeyPair pair)
	{
		this.clientID = clientID;
		this.pair = pair;
	}
	
	public int getID()
	{
		return this.clientID;
	}
	
	public KeyPair getKeyPair()
	{
		return this.pair;
	}
	
	public static Client generateNewClient() throws NoSuchAlgorithmException, CoseException
	{
		
		SCCKeyPair pair = SCCKeyPair.createKeyPair(KeyPairUseCase.Signing);
		PublicKey publicKey = pair.getPublicKey();
		PrivateKey privateKey = pair.getPrivateKey();
		//TODO: create method sendPublicKey
		int clientID = sendPublicKey(publicKey);
		Client c = new Client(clientID, pair.getKeyPair());
		clients.add(c);
		return c;
	}
	
	public void sendPublicKey(PublicKey publicKey)
	{
		//TODO: send public key to Server
	}
	

	public static byte[] generateOrder(TransactionType type) {
		
		String ISIN = generateRandomNumber(4);
		String amount = generateRandomNumber(3);
		String order = type.toString() + ";" + ISIN + ";" + amount;
		return order.getBytes();
	}
	
	public static String sign(byte[] order, KeyPair pair) throws CoseException
	{
		SecureCryptoConfig scc = new SecureCryptoConfig();
		SCCKeyPair sccPair = null;
		//SCCKeyPair sccPair = new SCCKeyPair(pair);
		SCCSignature sig = scc.sign(sccPair, order);
		return sig.toString();
	}
	
	public void sendOrder(int clientID, byte[] order) throws CoseException
	{
		KeyPair pair = this.pair;
		String signature = sign(order, pair);
		
		//TODO: send signature, order and clientID to Server
	}

	
	private static String generateRandomNumber(int length) {
		
		String AlphaNumericString = "01234567890"; 
		StringBuilder sb = new StringBuilder(length);

		for (int i = 0; i < length; i++) {
			int index = (int) (AlphaNumericString.length() * Math.random());
			sb.append(AlphaNumericString.charAt(index));
		}

		return sb.toString();
	}
}
