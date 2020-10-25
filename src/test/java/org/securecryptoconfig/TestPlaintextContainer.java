package org.securecryptoconfig;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.securecryptoconfig.SCCKey.KeyUseCase;

import COSE.CoseException;

public class TestPlaintextContainer {

    static SecureCryptoConfig scc;
    static String plaintext;
    static PlaintextContainer pc;
    static SCCKey symmetricKey;
    static SCCKey asymmetricKey;
    static SCCKey signingKey;

    @BeforeAll
    static void setup() {
        scc = new SecureCryptoConfig();
        plaintext = "Hello World!";
        pc = new PlaintextContainer(plaintext.getBytes(StandardCharsets.UTF_8));
        try {
            symmetricKey = SCCKey.createSymmetricKeyWithPassword("password".getBytes(StandardCharsets.UTF_8));
            asymmetricKey = SCCKey.createKey(KeyUseCase.AsymmetricEncryption);
            signingKey = SCCKey.createKey(KeyUseCase.Signing);
        } catch (SCCException e) {
            fail(e);
        } catch (CoseException e) {
            fail(e);
        }
    }

    @Test
    void testValidateHash() {
        try {
            assertTrue(pc.validateHash(pc.hash()));
        } catch (SCCException e) {
            fail(e);
        }
    }

    @Test
    void testValidatePasswordHash() {
        try {
            assertTrue(pc.validatePasswordHash(pc.passwordHash()));
        } catch (SCCException e) {
            fail(e);
        }
    }

    @Test
    void testEncryptSymmetric() {
        try {
            SCCCiphertext ciphertext = pc.encryptSymmetric(symmetricKey);
            String otherPlaintext = ciphertext.decryptSymmetric(symmetricKey).toString(StandardCharsets.UTF_8);
            assertEquals(plaintext, otherPlaintext);
        } catch (SCCException e) {
            fail(e);
        }
    }

    @Test
    void testEncryptAsymmetric() {
        try {
            SCCCiphertext ciphertext = pc.encryptAsymmetric(asymmetricKey);
            String otherPlaintext = ciphertext.decryptAsymmetric(asymmetricKey).toString(StandardCharsets.UTF_8);
            assertEquals(plaintext, otherPlaintext);
        } catch (SCCException e) {
            fail(e);
        }
    }

    @Test
    void testSign() {
        try {
            SCCSignature signature = pc.sign(signingKey);

            String otherPlaintext = "Hello Malory!";
            PlaintextContainer otherPc = new PlaintextContainer(otherPlaintext.getBytes(StandardCharsets.UTF_8));
            SCCSignature otherSignature = otherPc.sign(signingKey);

            assertNotEquals(signature.toBase64(), otherSignature.toBase64());
        } catch (SCCException e) {
            fail(e);
        }
    }
}
