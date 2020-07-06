package main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import main.SecureCryptoConfig.SecurityLevel;

public class JSONReader {

	protected static String basePath = null;
	// JSON parser object to parse read file
	private static JSONParser jsonParser = new JSONParser();

	// Enum representing supported crypto use cases
	protected enum CryptoUseCase {
		SymmetricEncryption, Signing, Hashing, AsymmetricEncryption, PasswordHashing, KeyGeneration;
	}

	/**
	 * retrieving Algorithms for specific Crypto Use case out of JSON
	 * 
	 * @param useCase, value from Enum
	 */
	protected static ArrayList<String> getAlgos(CryptoUseCase useCase, String sccFilePath) {
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

	private static String getVersionSecurityLevel(String sccFilePath) {
		String result = "";
		try {
		FileReader reader = new FileReader(sccFilePath);
			// Read JSON file
			Object obj = jsonParser.parse(reader);
			JSONArray sccList = (JSONArray) obj;
			JSONObject scc = (JSONObject) sccList.get(0);
			
			result = result + (String) scc.get("Version");
			result = result + "," + (String) scc.get("SecurityLevel");
			return result;
		}catch(IOException | ParseException e)
		{
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
	@SuppressWarnings({ "unchecked", "unused" })
	private static void readJSON() {

		try (FileReader reader = new FileReader(basePath + "SCC_Security_Level_5_2020-0.json")) {
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

	protected static String getLatestSCC(SecurityLevel level) {
		HashMap<String, String> one = new HashMap<String, String>();
		HashMap<String, String> two = new HashMap<String, String>();
		HashMap<String, String> three = new HashMap<String, String>();
		HashMap<String, String> four = new HashMap<String, String>();
		HashMap<String, String> five = new HashMap<String, String>();
		String[] result;
		String latest = null;

		int highestYear = 2020;
		int highestPatch = 0;
		HashMap<String, String> list = null;

		switch (level) {
		case SecurityLevel_1:
			list = one;
			latest = "SCC_SecurityLevel_1_2020-0.json";
			break;
		case SecurityLevel_2:
			list = two;
			latest = "SCC_SecurityLevel_2_2020-0.json";
			break;
		case SecurityLevel_3:
			list = three;
			latest = "SCC_SecurityLevel_3_2020-0.json";
			break;
		case SecurityLevel_4:
			list = four;
			latest = "SCC_SecurityLevel_4_2020-0.json";
			break;
		case SecurityLevel_5:
			list = five;
			latest = "SCC_SecurityLevel_5_2020-0.json";
			break;
		}

		if (SecureCryptoConfig.ownPathSet == false)
		{
			basePath = getBasePath();
		}
		else {
			System.out.println("Here");
			basePath = SecureCryptoConfig.sccPath;
			System.out.println(basePath);
		}
		File folder = new File(basePath);
		File[] listOfFiles = folder.listFiles();
		//Define path of SCC files
		

		for (int i = 0; i < listOfFiles.length; i++) {
			if (listOfFiles[i].isFile() && listOfFiles[i].getName().contains(".json")) {
				String fileName = listOfFiles[i].getName();
				String path = basePath + fileName;
				String versionAndLevel = getVersionSecurityLevel(path);
				
				result = versionAndLevel.split(",");
			
				switch (result[1]) {
				case "1":
					one.put(fileName, result[0]);
					break;
				case "2":
					two.put(fileName, result[0]);
				case "3":
					three.put(fileName, result[0]);
					break;
				case "4":
					four.put(fileName, result[0]);
					break;
				case "5":
					five.put(fileName, result[0]);
					break;
				}
			}
		}

		Set<String> keys = list.keySet();
		for (String s : keys) {
			String nmb = list.get(s);
			String version[] = nmb.split("-");
			Integer versionInt[] = new Integer[2];
			versionInt[0] = Integer.parseInt(version[0]);
			versionInt[1] = Integer.parseInt(version[1]);
			if (highestYear < versionInt[0]) {
				latest = s;
				highestYear = versionInt[0];

			} else if (highestYear == versionInt[0]) {
				if (highestPatch < versionInt[1]) {
					highestPatch = versionInt[1];
					latest = s;
				}
			}
		}

		return latest ;

	}

	public static void downloadSCCs() {
		// first delete old SCCs before getting new ones
		basePath = getBasePath();

		File f = new File(basePath + "SCC");
		if (f.exists()) {
			try {
				deleteDirectoryRecursion(Paths.get(basePath + "SCC"));
			} catch (IOException e1) {
				e1.printStackTrace();
			}
		}

		// retrieve Repo as ZIP
		try {
			// Path to repo with SCCs
			String url = "https://github.com/secureCryptoConfig/secureCryptoConfig/zipball/master/";
			FileOutputStream fileOutputStream = new FileOutputStream(basePath + "scc.zip");
			fileOutputStream.getChannel().transferFrom(Channels.newChannel(new URL(url).openStream()), 0,
					Long.MAX_VALUE);
			fileOutputStream.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

		// Unzip ZIP file
		try {
			Path targetDir = Paths.get(basePath);
			InputStream is = new FileInputStream(basePath + "scc.zip");
			ZipInputStream zipIn = new ZipInputStream(is);
			for (ZipEntry ze; (ze = zipIn.getNextEntry()) != null;) {
				Path resolvedPath = targetDir.resolve(ze.getName());
				if (ze.isDirectory()) {
					Files.createDirectories(resolvedPath);
				} else {
					Files.createDirectories(resolvedPath.getParent());
					Files.copy(zipIn, resolvedPath);
				}
			}
			zipIn.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		// delete downloaded ZIP
		try {
			deleteDirectoryRecursion(Paths.get(basePath + "scc.zip"));
		} catch (IOException e1) {
			e1.printStackTrace();
		}

	}

	private static void deleteDirectoryRecursion(Path path) throws IOException {
		if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
			try (DirectoryStream<Path> entries = Files.newDirectoryStream(path)) {
				for (Path entry : entries) {
					deleteDirectoryRecursion(entry);
				}
			}
		}
		Files.delete(path);
	}

	private static String getBasePath() {
		try {
			basePath = new File(JSONReader.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getPath()
					.replace("\\target\\classes", "");
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}
		return basePath = basePath + "\\src\\configs\\";
	}


}
