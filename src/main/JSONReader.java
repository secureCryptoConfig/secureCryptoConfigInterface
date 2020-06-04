package main;

import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class JSONReader {

	// JSON parser object to parse read file
	static JSONParser jsonParser = new JSONParser();

	// Enum representing supported crypto use cases
	public enum CryptoUseCase {
		SymmetricEncryption, Signing, Hashing, AsymmetricEncryption;
	}

	/**
	 * retrieving Algorithms for specific Crypto Use case out of JSON
	 * 
	 * @param useCase, value from Enum
	 */
	public static ArrayList<String> getAlgos(CryptoUseCase useCase) {
		ArrayList<String> algos = new ArrayList<String>();
		try (FileReader reader = new FileReader(".\\src\\main\\scc_example.json")) {
			// Read JSON file
			Object obj = jsonParser.parse(reader);
			JSONArray sccList = (JSONArray) obj;
			JSONObject scc = (JSONObject) sccList.get(0);

			JSONObject usageObject = (JSONObject) scc.get("Usage");
			JSONArray use = (JSONArray) usageObject.get(useCase.toString());
			Iterator<?> iterator = use.iterator();
			while (iterator.hasNext()) {
				// System.out.println(iterator.next());
				algos.add((String) iterator.next());
			}
			return algos;
		} catch (IOException | ParseException e) {
			e.printStackTrace();
			return null;
		}

	}

	/**
	 * Auxiliary method for readJSON method Prints all names/URL from each publisher
	 * 
	 * @param publisher
	 */
	private static void getPublisher(JSONObject publisher) {

		// Get publisher name
		String name = (String) publisher.get("name");
		System.out.println(name);

		String url = (String) publisher.get("URL");
		System.out.println(url);

	}

	/**
	 * Auxiliary method for readJSON method Prints all algorithms for a given
	 * useCase
	 * 
	 */

	private static void getUsage(CryptoUseCase useCase, JSONObject usageObject) {
		System.out.println(useCase.toString());
		JSONArray use = (JSONArray) usageObject.get(useCase.toString());
		Iterator<?> iterator = use.iterator();
		while (iterator.hasNext()) {
			System.out.println(iterator.next());
		}

	}

	/**
	 * Prints all data contained in the JSON file
	 */
	@SuppressWarnings("unchecked")
	public static void readJSON() {

		try (FileReader reader = new FileReader(".\\src\\main\\scc_example.json")) {
			// Read JSON file
			Object obj = jsonParser.parse(reader);

			JSONArray sccList = (JSONArray) obj;
			System.out.println(sccList);

			JSONObject scc = (JSONObject) sccList.get(0);

			String policyName = (String) scc.get("PolicyName");
			System.out.println(policyName);

			JSONArray publisherObject = (JSONArray) scc.get("Publisher");
			publisherObject.forEach(publisher -> getPublisher((JSONObject) publisher));

			String version = (String) scc.get("Version");
			System.out.println(version);

			String policyIssueDate = (String) scc.get("PolicyIssueDate");
			System.out.println(policyIssueDate);

			String expiry = (String) scc.get("Expiry");
			System.out.println(expiry);

			JSONObject usageObject = (JSONObject) scc.get("Usage");
			Arrays.asList(CryptoUseCase.values()).forEach(useCase -> getUsage(useCase, usageObject));

		} catch (IOException | ParseException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		String s = "AES_GCM_256_128_128";
		String[] parameters = s.split("_");
		for (int i = 0; i < parameters.length; i++) {
			System.out.println(parameters[i]);
		}
	}
}
