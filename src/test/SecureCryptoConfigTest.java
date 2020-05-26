package test;

import static org.junit.jupiter.api.Assertions.*;
import main.SecureCryptoConfig;

import org.junit.jupiter.api.Test;

class SecureCryptoConfigTest {

	SecureCryptoConfig s = new SecureCryptoConfig();
	
	@Test
	void test() {
		assertEquals(4, s.add(2,2));
	}

}
