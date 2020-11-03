package org.securecryptoconfig;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.stream.Stream;

import org.securecryptoconfig.SCCKey.KeyType;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Class for handling/parsing SCC file content
 * 
 * @author Lisa
 *
 */
public class JSONReader {

	private static org.apache.logging.log4j.Logger logger = org.apache.logging.log4j.LogManager
			.getLogger(JSONReader.class);

	private static ArrayList<Path> allFilePaths = new ArrayList<>();
	private static ArrayList<Path> publicKeyPaths = new ArrayList<>();
	protected static final HashSet<Integer> levels = new HashSet<>();

	static FileSystem fileSystem;

	protected static boolean isJAR = false;

	private static String signatureAlgo = "EC";

	private static String JsonFileEndingWithDot = ".json";

	// Enum representing supported crypto use cases
	protected enum CryptoUseCase {
		SymmetricEncryption, Signing, Hashing, AsymmetricEncryption, PasswordHashing, KeyGeneration;
	}

	/**
	 * Find the path to the specified policyName
	 * 
	 * @param policyName: of the Secure Crypto Config to use
	 * @return instance
	 */
	protected static SCCInstance findPathForPolicy(String policyName) {
		SCCInstance instance = null;
		for (int i = 0; i < instances.size(); i++) {
			if (instances.get(i).getPolicyName().equals(policyName)) {
				instance = instances.get(i);
				break;
			}
		}
		return instance;
	}

	/**
	 * Get all files out of root "configs" directory of given path
	 * 
	 * @param path to root directory "config"
	 */
	private static void getFiles(Path path) {

		URI uri;

		if (!SecureCryptoConfig.customPath) {
			try {
				uri = JSONReader.class.getResource("/scc-configs").toURI();

				if (uri.getScheme().equals("jar")) {
					fileSystem = FileSystems.newFileSystem(uri, Collections.<String, Object>emptyMap());
					path = fileSystem.getPath("/scc-configs");
					isJAR = true;
				} else {
					path = Paths.get(uri);
					isJAR = false;
				}
			} catch (URISyntaxException | IOException e) {
				logger.warn("Custom Path invalid or not available", e);
				return;
			}
		}

		Stream<Path> stream = null;
		try {
			stream = Files.walk(path);
			stream.filter(Files::isRegularFile)
					.filter(file -> file.getFileName().toString().endsWith(JsonFileEndingWithDot))
					.forEach(file -> allFilePaths.add(file));
			stream.close();
		} catch (IOException | NullPointerException e) {
			logger.warn("Path not available or not set", e);
		} finally {
			if (stream != null) {
				stream.close();
			}
		}
	}

	protected static ArrayList<SCCInstance> instances = new ArrayList<>();

	private static void getSCCInstances() {
		levels.clear();
		ObjectMapper objectMapper = new ObjectMapper();
		int level;
		String version;

		try {
			for (int i = 0; i < allFilePaths.size(); i++) {
				SCCInstance sccInstance;
				if (!isJAR) {
					sccInstance = objectMapper.readValue(new File(allFilePaths.get(i).toString()), SCCInstance.class);
				} else {
					InputStream is = org.securecryptoconfig.JSONReader.class
							.getResourceAsStream(allFilePaths.get(i).toString());
					sccInstance = objectMapper.readValue(is, SCCInstance.class);
				}
				// check securityLevel, version format
				level = sccInstance.getSecurityLevel();
				version = sccInstance.getVersion();
				if (level > 0 && version.matches("^[2]\\d{3}-\\d+")) {
					levels.add(level);
					instances.add(sccInstance);
				} else {
					break;
				}
			}
		} catch (IOException e) {
			logger.warn("Error while trying to access JSON files", e);
		}
	}

	/**
	 * Determines path to latest SCC file with given Security level
	 * 
	 * @param level
	 * @return path to latest SCC file with given Security level
	 */
	protected static SCCInstance getLatestSCC(int level) {
		SCCInstance latest = null;
		ArrayList<SCCInstance> instancesWithLevel = new ArrayList<>();

		if (levels.contains(level)) {
			// which file have security level
			for (SCCInstance instance : instances) {
				if (instance.getSecurityLevel() == level) {
					instancesWithLevel.add(instance);
				}
			}

			int highestYear = 0;
			int highestPatch = 0;

			for (SCCInstance i : instancesWithLevel) {
				String nmb = i.getVersion();
				String[] version = nmb.split("-");
				Integer[] versionInt = new Integer[2];
				versionInt[0] = Integer.parseInt(version[0]);
				versionInt[1] = Integer.parseInt(version[1]);
				if (highestYear < versionInt[0]) {
					latest = i;
					highestYear = versionInt[0];

				} else if (highestYear == versionInt[0] && highestPatch < versionInt[1]) {
					highestPatch = versionInt[1];
					latest = i;
				}
			}
			return latest;
		} else {
			throw new IllegalArgumentException("No file for the specified Security Level Number");
		}
	}

	/**
	 * Determines the highest Security Level number in Set
	 * 
	 * @param level Hashset with all appearing Security Level numbers
	 * @return highest appearing level
	 */
	protected static int getHighestLevel(HashSet<Integer> level) {

		return Collections.max(level);
	}

	/**
	 * Check signature from SCC files
	 * @param algo
	 * @param signaturePath
	 * @param publicKeyPath
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws SCCException
	 * @throws InvalidKeySpecException
	 */
	private static boolean checkSignature(String algo, String signaturePath, String publicKeyPath)
			throws IOException, NoSuchAlgorithmException, SCCException, InvalidKeySpecException {

		byte[] publicKey;
		byte[] sig;
		if (!isJAR) {
			Path fileLocation = Paths.get(publicKeyPath);
			publicKey = Files.readAllBytes(fileLocation);

			Path fileLocation1 = Paths.get(signaturePath);
			sig = Files.readAllBytes(fileLocation1);

		} else {
			InputStream is = org.securecryptoconfig.JSONReader.class.getResourceAsStream(publicKeyPath);
			publicKey = is.readAllBytes();
			is.close();
			InputStream is1 = org.securecryptoconfig.JSONReader.class.getResourceAsStream(signaturePath);
			sig = is1.readAllBytes();
			is1.close();
		}

		PublicKey pub = KeyFactory.getInstance(algo).generatePublic(new X509EncodedKeySpec(publicKey));

		SCCKey key = new SCCKey(KeyType.Asymmetric, pub.getEncoded(), null, algo);

		SCCSignature signature = SCCSignature.createFromExistingSignature(sig);

		return signature.validateSignature(key);

	}

	/**
	 * Method to determine where the public keys for the validation of the
	 * signature from the SCC files can be found
	 * @param path
	 */
	private static void getPublicKeyPath(Path path) {
		URI uri;
		Path p = null;
		try {
			uri = JSONReader.class.getResource("/scc-configs/publicKeys").toURI();

			if (isJAR) {
				p = fileSystem.getPath("/scc-configs/publicKeys");
			} else {
				if (!SecureCryptoConfig.customPath) {
					p = Paths.get(uri);
				} else {
					p = Paths.get(path.toString() + "\\publicKeys");
				}
			}
		} catch (URISyntaxException e) {
			logger.warn("public key path not valid", e);
		}
		Stream<Path> s = null;
		try {
			s = Files.walk(p);
			s.filter(Files::isRegularFile).filter(file -> file.getFileName().toString().startsWith("publicKey"))
					.forEach(file -> publicKeyPaths.add(file));
		} catch (IOException e) {
			logger.warn("Error while trying to access file", e);
		} finally {
			if (s != null) {
				s.close();
			}
		}
	}

	private static void startValidation() throws SCCException {
		InputStream is1;
		InputStream is2;
		for (int i = 0; i < allFilePaths.size(); i++) {
			Path filepath = allFilePaths.get(i);
			String[] parts = allFilePaths.get(i).toString().split("\\\\");
			String signatureFileName1 = parts[parts.length - 1].replace(JsonFileEndingWithDot, "-signature1");
			String signatureFileName2 = parts[parts.length - 1].replace(JsonFileEndingWithDot, "-signature2");
			String signaturePath1 = filepath.toString().replace(parts[parts.length - 1], "") + signatureFileName1;
			String signaturePath2 = filepath.toString().replace(parts[parts.length - 1], "") + signatureFileName2;

			boolean result;
			if (!isJAR) {
				result = new File(signaturePath1).exists() && new File(signaturePath2).exists();
			} else {
				is1 = org.securecryptoconfig.JSONReader.class.getResourceAsStream(signaturePath1);
				is2 = org.securecryptoconfig.JSONReader.class.getResourceAsStream(signaturePath2);
				result = is1 != null && is2 != null;
				closingStreams(is1, is2);
				
			}

			if (result) {
				calculateValidationResult(signaturePath1, signaturePath2, filepath, i);
			} else {
				logger.debug("There are no two signatures defined for {}", filepath);
				logger.debug("This file will not be considered!");
				allFilePaths.remove(i);
			}

		}

	}
	
	/**
	 * Auxiliary method to look if opened streams must be closed 
	 * @param is1
	 * @param is2
	 */
	private static void closingStreams(InputStream is1, InputStream is2)
	{
		try {
			if (is1 != null) {
				is1.close();
			}
			if (is2 != null) {
				is2.close();
			}
		} catch (IOException e) {
			logger.warn("Error while trying to validate JSON files", e);
		}
	}
	
	/**
	 * Auxiliary method to get the validation results of the SCC file signatures
	 * @param signaturePath1
	 * @param signaturePath2
	 * @param filepath
	 * @param i
	 * @throws SCCException
	 */
	private static void calculateValidationResult(String signaturePath1, String signaturePath2, Path filepath, int i) throws SCCException
	{

		boolean validation1 = false;
		boolean validation2 = false;

		try {
			validation1 = checkSignature(signatureAlgo, signaturePath1, publicKeyPaths.get(0).toString());
			validation2 = checkSignature(signatureAlgo, signaturePath2, publicKeyPaths.get(1).toString());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
			throw new SCCException("Signature check of Secure Crypto Config files could not be performed!", e);
		}
	
		if (!validation1 || !validation2) {
			logger.debug("Not both signatures are valid for {}", filepath);
			logger.debug("This file will not be considered!");
			allFilePaths.remove(i);
		}
	
	}

	/**
	 * Determine path to latest SCC file with highest appearing Security Level
	 * number
	 * 
	 * @param path to "configs" folder containing SCC files
	 * @return path
	 */
	protected static SCCInstance parseFiles(Path path) {
		publicKeyPaths.clear();
		allFilePaths.clear();
		instances.clear();

		getFiles(path);
		getSCCInstances();
		getPublicKeyPath(path);

		try {
			startValidation();
		} catch (SCCException e) {
			logger.warn("Error in validation of SCC files", e);
		}

		return getLatestSCC(getHighestLevel(levels));

	}

}
