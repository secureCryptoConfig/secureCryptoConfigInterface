package main;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import com.mifmif.common.regex.Generex;

public class JSONReader {

	// JSON parser object to parse read file
	static JSONParser jsonParser = new JSONParser();

	// Enum representing supported crypto use cases
	public enum CryptoUseCase {
		SymmetricEncryption, Signing, Hashing, AsymmetricEncryption, PasswordHashing, KeyGeneration;
	}

	/**
	 * retrieving Algorithms for specific Crypto Use case out of JSON
	 * 
	 * @param useCase, value from Enum
	 */
	public static ArrayList<String> getAlgos(CryptoUseCase useCase, String sccFilePath) {
		ArrayList<String> algos = new ArrayList<String>();
		try (FileReader reader = new FileReader(sccFilePath)) {
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

	final static String UrlJSON = "https://raw.githubusercontent.com/secureCryptoConfig/secureCryptoConfig/master/src/";
	final static String prefix = "SCC_SecurityLevel_";
	public static void downloadAllJSONFile() {
		String s, url, filename = "";
		Generex generex = new Generex("[1-5]_(2020|2023|2026|2027|2030)-([0-9]|[1-9][0-9])");
		// Generex generex = new
		// Generex("(scc_example|scc_example_extended|scc_general)");

		// Using Generex iterator
		com.mifmif.common.regex.util.Iterator iterator = generex.iterator();
		while (iterator.hasNext()) {
			s = prefix + iterator.next();
			// s = iterator.next();
			filename = s + ".json";
			url = UrlJSON + filename;
			System.out.println(filename);

			try {
				BufferedInputStream in = new BufferedInputStream(new URL(url).openStream());
				File f = new File(".\\src\\main\\" + filename);
				f.createNewFile();
				FileOutputStream fileOutputStream = new FileOutputStream(".\\src\\main\\" + filename);
				byte dataBuffer[] = new byte[1024];
				int bytesRead;
				while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
					fileOutputStream.write(dataBuffer, 0, bytesRead);
				}
				fileOutputStream.close();
			} catch (IOException e) {
				continue;
			}

		}

	}

	public static String getLatestSCC(int securityLevel) {
		HashMap<String, String> one = new HashMap<String, String>();
		HashMap<String, String> two = new HashMap<String, String>();
		HashMap<String, String> three = new HashMap<String, String>();
		HashMap<String, String> four = new HashMap<String, String>();
		HashMap<String, String> five = new HashMap<String, String>();
		String[] result;
		String filename = "";
		String latest = null;
		
		int highestYear = 2020;
		int highestPatch = 0;
		HashMap<String, String> list = null;
		
		Generex generex = new Generex("[1-5]_(2020|2023|2026|2027|2030)-([0-9]|[1-9][0-9])");
		


		switch (securityLevel) {
		case 1:
			list = one;
			latest = "SCC_SecurityLevel_1_2020-0";
			break;
		case 2:
			list = two;
			latest = "SCC_SecurityLevel_2_2020-0";
			break;
		case 3:
			list = three;
			latest = "SCC_SecurityLevel_3_2020-0";
			break;
		case 4:
			list = four;
			latest = "SCC_SecurityLevel_4_2020-0";
			break;
		case 5:
			list = five;
			latest = "SCC_SecurityLevel_5_2020-0";
			break;
		}

		// For all names
		com.mifmif.common.regex.util.Iterator iterator = generex.iterator();
		while (iterator.hasNext()) {
			filename = prefix + iterator.next();
			File f = new File(".\\src\\main\\" + filename + ".json");
			if (f.exists()) {

				result = filename.split("_");
				switch (result[2]) {
				case "1":
					one.put(filename, result[3]);
				case "2":
					two.put(filename, result[3]);
				case "3":
					three.put(filename, result[3]);
				case "4":
					four.put(filename, result[3]);
				case "5":
					five.put(filename, result[3]);
				}
			}
		}

		com.mifmif.common.regex.util.Iterator iterator1 = generex.iterator();
		while (iterator1.hasNext()) {
			filename = prefix + iterator1.next();
			for (int i = 0; i < list.size(); i++) {
				if (list.containsKey(filename)) {
					String nmb = list.get(filename);
					String version[] = nmb.split("-");
					Integer versionInt[] = new Integer[2];
					versionInt[0] = Integer.parseInt(version[0]);
					versionInt[1] = Integer.parseInt(version[1]);
					if (highestYear < versionInt[0]) {
						latest = filename;
						highestYear = versionInt[0];

					} else if (highestYear == versionInt[0]) {
						if (highestPatch < versionInt[1]) {
							highestPatch = versionInt[1];
							latest = filename;
						}
					}
				}
			}
		}

		return latest + ".json";

	}

	public static void main(String[] args) {
		// downloadAllJSONFile();
		String i = getLatestSCC(2);
		System.out.println(i);
		
	}
}
