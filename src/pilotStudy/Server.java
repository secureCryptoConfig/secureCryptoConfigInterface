package pilotStudy;

import java.security.InvalidKeyException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.securecryptoconfig.SCCCiphertext;
import org.securecryptoconfig.SCCException;
import org.securecryptoconfig.SCCKey;
import org.securecryptoconfig.SecureCryptoConfig;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import COSE.CoseException;

public class Server extends Thread {
	final static String masterPassword = "Confidential";
	static SCCKey masterKey = null;
	List<SCCKey> clients = Collections.synchronizedList(new ArrayList<SCCKey>());

	public synchronized int registerClient(SCCKey key) {

		if (clients.indexOf(key) == -1) {
			clients.add(key);
		}

		return clients.indexOf(key);
	}

	private boolean checkSignature(int clientID, byte[] order, byte[] signature) throws CoseException {
		SCCKey key = clients.get(clientID);
		SecureCryptoConfig scc = new SecureCryptoConfig();

		boolean resultValidation;
		try {
			resultValidation = scc.validateSignature(key, signature);
			if (resultValidation == true) {
				encryptOrder(order);
			}
		} catch (InvalidKeyException | SCCException e) {
			e.printStackTrace();
			return false;
		}
		
		return resultValidation;

	}

	private void encryptOrder(byte[] order) throws CoseException {
		try {
			masterKey = SCCKey.createSymmetricKeyWithPassword(masterPassword.getBytes());
		} catch (SCCException e1) {
			e1.printStackTrace();
		}
		
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
