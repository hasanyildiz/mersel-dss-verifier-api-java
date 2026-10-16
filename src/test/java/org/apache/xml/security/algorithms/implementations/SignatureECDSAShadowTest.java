/*
 * MERSEL OVERRIDE testi — Santuario SignatureECDSA sınıfyolu gölgesi.
 *
 * Testler src/main/java altındaki kopyanın xmlsec jar'ındaki orijinal yerine
 * yüklendiğini varsayar (target/classes bağımlılık jar'ından önce gelir).
 * derSignatureValue_verifiesWithoutChangingTheDocument orijinal sınıfla
 * geçemezdi: bu satır aynı zamanda gölgenin etkin olduğunun kanıtıdır.
 */
package org.apache.xml.security.algorithms.implementations;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * DER kodlu ECDSA SignatureValue (TÜBİTAK kripto süiti EC örnekleri, bazı mali mühür
 * üreticileri) belge değiştirilmeden doğrulanır; raw r||s davranışı aynen korunur.
 */
class SignatureECDSAShadowTest {

    private static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

    @BeforeAll
    static void init() {
        Init.init();
    }

    @Test
    void rawSignatureValue_stillVerifies() throws Exception {
        KeyPair keys = ecKeys("secp256r1");
        Element signature = signedDocument(keys);
        assertTrue(new XMLSignature(signature, "").checkSignatureValue(keys.getPublic()));
    }

    /** Gölge kanıtı: orijinal Santuario DER değeri raw sanıp ikiye böler ve false döner. */
    @Test
    void derSignatureValue_verifiesWithoutChangingTheDocument() throws Exception {
        for (String curve : Arrays.asList("secp256r1", "secp384r1", "secp521r1")) {
            KeyPair keys = ecKeys(curve);
            Element signature = signedDocument(keys);
            byte[] raw = signatureValue(signature);
            setSignatureValue(signature, SignatureECDSA.convertXMLDSIGtoASN1(raw));
            assertTrue(new XMLSignature(signature, "").checkSignatureValue(keys.getPublic()), curve);
        }
    }

    @Test
    void tamperedDerSignatureValue_fails() throws Exception {
        KeyPair keys = ecKeys("secp256r1");
        Element signature = signedDocument(keys);
        byte[] der = SignatureECDSA.convertXMLDSIGtoASN1(signatureValue(signature));
        der[der.length - 1] ^= 0x01;
        setSignatureValue(signature, der);
        assertFalse(new XMLSignature(signature, "").checkSignatureValue(keys.getPublic()));
    }

    /**
     * Sabit genişlikli INTEGER'lı DER (gereksiz baştaki sıfır / işaret baytı eksik):
     * kaldırılan preprocessor bunu kabul ediyordu, gölge de kanonik DER'e çevirip doğrular.
     */
    @Test
    void fixedWidthDerSignatureValue_verifies() throws Exception {
        for (String curve : Arrays.asList("secp256r1", "secp384r1", "secp521r1")) {
            KeyPair keys = ecKeys(curve);
            Element signature = signedDocument(keys);
            byte[] raw = signatureValue(signature);
            setSignatureValue(signature, fixedWidthDer(raw, 0));
            assertTrue(new XMLSignature(signature, "").checkSignatureValue(keys.getPublic()), curve + " işaretsiz");
            setSignatureValue(signature, fixedWidthDer(raw, 1));
            assertTrue(new XMLSignature(signature, "").checkSignatureValue(keys.getPublic()), curve + " 0x00 önekli");
        }
    }

    @Test
    void derDetection_returnsJcaOutputUnchangedForAllCurves() throws Exception {
        for (String curve : Arrays.asList("secp256r1", "secp384r1", "secp521r1")) {
            KeyPair keys = ecKeys(curve);
            Signature jca = Signature.getInstance("SHA256withECDSA");
            jca.initSign(keys.getPrivate());
            jca.update(new byte[] {1, 2, 3});
            byte[] der = jca.sign();
            assertArrayEquals(der, SignatureECDSA.derEcdsaSignature(der), curve);
        }
    }

    @Test
    void derDetection_rejectsRawAndMalformedValues() throws Exception {
        byte[] raw = signatureValue(signedDocument(ecKeys("secp256r1")));
        byte[] der = SignatureECDSA.convertXMLDSIGtoASN1(raw);
        assertNotNull(SignatureECDSA.derEcdsaSignature(der));
        assertNull(SignatureECDSA.derEcdsaSignature(raw));
        assertNull(SignatureECDSA.derEcdsaSignature(new byte[64]));
        assertNull(SignatureECDSA.derEcdsaSignature(Arrays.copyOf(der, der.length + 1)), "fazla bayt");
        assertNull(SignatureECDSA.derEcdsaSignature(Arrays.copyOf(der, der.length - 1)), "eksik bayt");
        assertNull(SignatureECDSA.derEcdsaSignature(null));
    }

    // ------------------------------------------------------------ yardımcılar

    private static KeyPair ecKeys(String curve) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    /** Santuario ile imzalanmış enveloped belge; SignatureValue raw r||s. */
    private static Element signedDocument(KeyPair keys) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        Document document = factory.newDocumentBuilder().newDocument();
        Element root = document.createElement("Invoice");
        root.setTextContent("EC imza testi");
        document.appendChild(root);
        XMLSignature signature = new XMLSignature(document, "", XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256);
        root.appendChild(signature.getElement());
        Transforms transforms = new Transforms(document);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        signature.addDocument("", transforms, SHA256);
        signature.sign(keys.getPrivate());
        return signature.getElement();
    }

    /** raw r||s → her INTEGER'ı yarı uzunlukta (+ önek sıfır) tutan, en kısa olmayan DER. */
    private static byte[] fixedWidthDer(byte[] raw, int zeroPrefix) {
        int half = raw.length / 2;
        int integerLength = half + zeroPrefix;
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        for (int i = 0; i < 2; i++) {
            body.write(0x02);
            body.write(integerLength);
            for (int z = 0; z < zeroPrefix; z++) {
                body.write(0);
            }
            body.write(raw, i * half, half);
        }
        ByteArrayOutputStream der = new ByteArrayOutputStream();
        der.write(0x30);
        if (body.size() >= 0x80) {
            der.write(0x81);
        }
        der.write(body.size());
        byte[] content = body.toByteArray();
        der.write(content, 0, content.length);
        return der.toByteArray();
    }

    private static Element signatureValueElement(Element signature) {
        return (Element) signature.getElementsByTagNameNS(Constants.SignatureSpecNS, "SignatureValue").item(0);
    }

    private static byte[] signatureValue(Element signature) {
        return Base64.getMimeDecoder().decode(signatureValueElement(signature).getTextContent());
    }

    private static void setSignatureValue(Element signature, byte[] value) {
        signatureValueElement(signature).setTextContent(Base64.getEncoder().encodeToString(value));
    }
}
