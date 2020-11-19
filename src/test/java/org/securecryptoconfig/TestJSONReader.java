package org.securecryptoconfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidParameterException;

import org.junit.jupiter.api.Test;

public class TestJSONReader {

	// Tests for SCC files handling
	@Test
	void testSCCFileHandling() throws URISyntaxException, SCCException {
		// Set security level and get the policy name of the SCC file currently used
		SecureCryptoConfig.setSecurityLevel(5);
		String policyName = SecureCryptoConfig.getUsedSCC();
		assertEquals("SCC_SecurityLevel_5", policyName);

		// Set not existing security level
		assertThrows(IllegalArgumentException.class, () -> SecureCryptoConfig.setSecurityLevel(7));

		// Go back to default SCC
		SecureCryptoConfig.setDefaultSCC();
		
		String policyName1 = SecureCryptoConfig.getUsedSCC();
		assertEquals("SCC_SecurityLevel_5", policyName1);

		// Set specific SCC file with desired policyName
		SecureCryptoConfig.setSCCFile("SCC_SecurityLevel_5");
		String policyName2 = SecureCryptoConfig.getUsedSCC();
		assertEquals("SCC_SecurityLevel_5", policyName2);

		// Set specific SCC file with not existing policyName
		assertThrows(InvalidParameterException.class, () -> SecureCryptoConfig.setSCCFile("WrongName"));

		// Set custom path that is not existing
		Path p = Paths.get("NoExistingPath");
		assertThrows(InvalidPathException.class, () -> SecureCryptoConfig.setCustomSCCPath(p));
		
		System.out.println(Paths.get(TestJSONReader.class.getResource("/scc-configs").toURI()));
		
		SecureCryptoConfig.setCustomSCCPath((Paths.get(TestJSONReader.class.getResource("/scc-configs").toURI())));
		//System.out.println(Paths.get(TestJSONReader.class.getResource("/scc-configs").toURI()));
	}

}
