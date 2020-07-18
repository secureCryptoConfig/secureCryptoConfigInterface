package pilotStudy;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import COSE.CoseException;
import main.SCCCiphertext;
import main.SCCKey;
import main.SecureCryptoConfig;

public class Server extends Thread {
	final static String masterPassword = "Confidential";
	private static SCCKey masterKey = null;
	List<SCCKey> clients = Collections.synchronizedList(new ArrayList<SCCKey>());

	public Server() {
		try {
			this.masterKey = SCCKey.createSymmetricKeyWithPassword(masterPassword.getBytes());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | CoseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public synchronized int registerClient(SCCKey key) {

		if (clients.indexOf(key) == -1) {
			clients.add(key);
		}

		return clients.indexOf(key);
	}

	private boolean checkSignature(int clientID, byte[] order, byte[] signature) throws CoseException {
		SCCKey key = clients.get(clientID);
		SecureCryptoConfig scc = new SecureCryptoConfig();

		boolean resultValidation = false;
		try {
			resultValidation = scc.validateSignature(key, signature);
			if (resultValidation == true) {
				encryptOrder(order);
			}
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return false;
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return resultValidation;

	}

	private void encryptOrder(byte[] order) throws CoseException {
		SecureCryptoConfig scc = new SecureCryptoConfig();
		try {
			SCCCiphertext cipher = scc.encryptSymmetric(masterKey, order);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

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

			byte[] signature = signedMessage.getSignature();

			isCorrectMessage = checkSignature(clientId, signedMessage.getContent().getBytes(), signature);

			Message theMessage = mapper.readValue(signedMessage.getContent(), Message.class);

			p(theMessage.getMessageType().toString());
		} catch (JsonProcessingException | CoseException e) {
			e.printStackTrace();
		}

		// SAVE Message
		try {
			return Message.createServerResponsekMessage(isCorrectMessage);
		} catch (JsonProcessingException e) {
			return new String("{\"Failure\"}");
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
