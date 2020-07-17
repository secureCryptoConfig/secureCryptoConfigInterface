package pilotStudy;

import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import COSE.CoseException;
import main.SCCCiphertext;
import main.SCCKey;
import main.SCCKey.KeyType;
import main.SCCKeyPair;
import main.SecureCryptoConfig;

public class Server extends Thread {
	final static String masterPassword = "Confidential";

	List<byte[]> clients = Collections.synchronizedList(new ArrayList<byte[]>());

	public synchronized int registerClient(byte[] publicKey) {

		if (clients.indexOf(publicKey) == -1) {
			clients.add(publicKey);
		}

		return clients.indexOf(publicKey);
	}

	private boolean checkSignature(int clientID, byte[] order, byte[] signature) throws CoseException {
		byte[] publicKey = clients.get(clientID);
		SecureCryptoConfig scc = new SecureCryptoConfig();

		SCCKey keyPair = new SCCKey(KeyType.Asymmetric, publicKey, null, "EC");
		
		boolean resultValidation = scc.validateSignature(keyPair, signature);
		if (resultValidation == true) {
			encryptOrder(order);
		}
		
		return resultValidation;

	}

	private void encryptOrder(byte[] order) throws CoseException {
		SecureCryptoConfig scc = new SecureCryptoConfig();
		SCCKey key = SCCKey.createSymmetricKeyWithPassword(masterPassword.getBytes());
		SCCCiphertext cipher = scc.encryptSymmetric(key, order);
		
		// TODO: store cipher as byte[] somewhere

	}

	public String acceptMessage(String message) {
		// TODO create something like this: OrderParser op = new OrderParser(PublicKey);
		// op.init(message) throws InvalidSignatureException ...

		boolean isCorrectMessage = false;

		ObjectMapper mapper = new ObjectMapper();
		try {
			SignedMessage signedMessage = mapper.readValue(message, SignedMessage.class);
			int clientId = signedMessage.getClientId();
			byte[] publicKey = clients.get(clientId);

			byte[] signature = signedMessage.getSignature();

			isCorrectMessage = checkSignature(clientId, signedMessage.getContent().getBytes(), signature);

			Message theMessage = mapper.readValue(signedMessage.getContent(), Message.class);

			p(theMessage.getMessageType().toString());
		} catch (JsonProcessingException | CoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// SAVE Message

		try {
			return Message.createServerResponsekMessage(isCorrectMessage);
		} catch (JsonProcessingException e) {
			// TODO Auto-generated catch block
			return new String("{\"Failure\"}");
			// e.printStackTrace();
		}
	}

	private void p(String s) {
		System.out.println(Instant.now().toString() + " server: " + s);
	}

	@Override
	public void run() {
		while (true) {
			p("processing orders");
			// TODO actually do something with the orders
			try {
				Thread.sleep(10000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				// e.printStackTrace();
			}
		}
	}

}
