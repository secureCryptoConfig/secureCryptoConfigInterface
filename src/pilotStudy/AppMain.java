package pilotStudy;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import COSE.CoseException;

public class AppMain {

	protected static HashSet<Client> clients = new HashSet<Client>();

	private static int maxClients = 5;

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Server server = new Server();
		ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newCachedThreadPool();
		executor.submit(server);

		try {
			for (int i = 0; i < maxClients; i++) {
				clients.add(Client.generateNewClient(server));
			}

		} catch (NoSuchAlgorithmException | CoseException | IllegalStateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		for (Client s : clients) {
			executor.submit(s);
		}

	}

	private static void p(String s) {
		System.out.println(Instant.now().toString() + "AppMain: " + s);
	}

}
