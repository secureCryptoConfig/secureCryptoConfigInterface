package pilotStudy;

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
import main.SCCKeyPair;
import main.SecureCryptoConfig;

public class Server extends Thread {
	final static String masterPassword = "Confidential";

	List<PublicKey> clients = Collections.synchronizedList(new ArrayList<PublicKey>());

	public synchronized int registerClient(PublicKey publicKey) {

		if (clients.indexOf(publicKey) == -1) {
			clients.add(publicKey);
		}

		return clients.indexOf(publicKey);
	}

	private void checkSignature(int clientID, byte[] order, byte[] signature) throws CoseException {
		PublicKey publicKey = clients.get(clientID);
		SecureCryptoConfig scc = new SecureCryptoConfig();

		// SCCKeyPair keyPair = new SCCKeyPair(new KeyPair(publicKey, null));
		SCCKeyPair keyPair = null;
		boolean resultValidation = scc.validateSignature(keyPair, signature);

		if (resultValidation == true) {
			encryptOrder(order);
		}

		// TODO: return some Info to client
	}

	private void encryptOrder(byte[] order) throws CoseException {
		SecureCryptoConfig scc = new SecureCryptoConfig();
		SCCKey key = SCCKey.createKeyWithPassword(masterPassword.getBytes());
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
			PublicKey publicKey = clients.get(clientId);

			byte[] signature = signedMessage.getSignature();

			// TODO validate signature

			Message theMessage = mapper.readValue(signedMessage.getContent(), Message.class);

			p(theMessage.getMessageType().toString());
		} catch (JsonProcessingException e) {
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
