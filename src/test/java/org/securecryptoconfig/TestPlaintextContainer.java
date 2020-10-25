package org.securecryptoconfig;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SCCKey.KeyUseCase;

import COSE.CoseException;

public class TestPlaintextContainer {

    SecureCryptoConfig scc = new SecureCryptoConfig();

    @Test
    void testValidateHash() {
        try {
            String testplaintext = "Hello World!";
            PlaintextContainer pc = new PlaintextContainer(testplaintext.getBytes(StandardCharsets.UTF_8));
            assertTrue(pc.validateHash(pc.hash()));
        } catch (SCCException e) {
            fail(e);
        }
    }

    @Test
    void testValidatePasswordHash() {
        try {
            String testplaintext = "Hello World!";
            PlaintextContainer pc = new PlaintextContainer(testplaintext.getBytes(StandardCharsets.UTF_8));
            assertTrue(pc.validatePasswordHash(pc.passwordHash()));
        } catch (SCCException e) {
            fail(e);
        }
    }

    @Test
    void testEncryptSymmetric() {
        try {
            String testPlaintext = "Hello World!";
            PlaintextContainer pc = new PlaintextContainer(testPlaintext.getBytes(StandardCharsets.UTF_8));
            SCCKey key = SCCKey.createSymmetricKeyWithPassword("password".getBytes(StandardCharsets.UTF_8));
            SCCCiphertext ciphertext = pc.encryptSymmetric(key);
            String plaintext = ciphertext.decryptSymmetric(key).toString(StandardCharsets.UTF_8);
            assertEquals(testPlaintext, plaintext);
        } catch (SCCException e) {
            fail(e);
        }
    }

    @Test
    void testEncryptAsymmetric() {
        try {
            String testPlaintext = "Hello World!";
            PlaintextContainer pc = new PlaintextContainer(testPlaintext.getBytes(StandardCharsets.UTF_8));
            SCCKey key = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
            SCCCiphertext ciphertext = pc.encryptAsymmetric(key);
            String plaintext = ciphertext.decryptAsymmetric(key).toString(StandardCharsets.UTF_8);
            assertEquals(testPlaintext, plaintext);
        } catch (SCCException e) {
            fail(e);
        } catch (CoseException e) {
            fail(e);
        }
    }

    @Test
    void testSign() {
        try {
            String testPlaintext = "Hello World!";
            PlaintextContainer pc = new PlaintextContainer(testPlaintext.getBytes(StandardCharsets.UTF_8));
            SCCKey key = SCCKey.createKey(KeyUseCase.Signing);
            SCCSignature signature = pc.sign(key);

            String otherPlaintext = "Hello Malory!";
            PlaintextContainer otherPc = new PlaintextContainer(otherPlaintext.getBytes(StandardCharsets.UTF_8));
            SCCSignature otherSignature = otherPc.sign(key);

            assertNotEquals(signature.toBase64(),otherSignature.toBase64());
        } catch (SCCException e) {
            fail(e);
        } catch (CoseException e) {
            fail(e);
        }
    }
}
