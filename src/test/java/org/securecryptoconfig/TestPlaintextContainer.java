package org.securecryptoconfig;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class TestPlaintextContainer {

    SecureCryptoConfig scc = new SecureCryptoConfig();

    @Test
    void testValidateHash() {
        try {
            String testplaintext = "Hello World!";
            PlaintextContainer pc = new PlaintextContainer(testplaintext.getBytes(StandardCharsets.UTF_8));
            assertTrue(pc.validateHash(pc.hash()));
        } catch (SCCException e) {

        }
    }

    @Test
    void testValidatePasswordHash() {
        try {
            String testplaintext = "Hello World!";
            PlaintextContainer pc = new PlaintextContainer(testplaintext.getBytes(StandardCharsets.UTF_8));
            assertTrue(pc.validatePasswordHash(pc.passwordHash()));
        } catch (SCCException e) {

        }
    }
}
