package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import io.mersel.dss.verify.api.config.VerificationConfiguration;
import io.mersel.dss.verify.api.models.AppliedRejection;
import io.mersel.dss.verify.api.models.SignatureInfo;
import io.mersel.dss.verify.api.models.enums.VerificationLevel;
import io.mersel.dss.verify.api.services.certificate.KamusmRootCertificateService;
import io.mersel.dss.verify.api.services.certificate.RequestTrustContext;
import io.mersel.dss.verify.api.services.util.LegacyTurkishXadesTypeUriDetector;
import io.mersel.dss.verify.api.services.util.RevocationInfoExtractor;
import io.mersel.dss.verify.api.services.util.XadesSignaturePackagingDetector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.util.ReflectionTestUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code MDSS-TR-KEYUSAGE-PROFILE} kararının DSS kararıyla ilişkisi, gerçek DSS
 * doğrulamasıyla. Her senaryo aynı imzalı belgeyi profil kontrolü kapalı ve açık
 * doğrular: kontrol yalnız DSS'in geçirdiği imzanın kararını değiştirir; DSS zaten
 * reddettiyse DSS'in kararı ve hata satırları aynen kalır, ihlal yalnız eklenir.
 *
 * <p>İmzacı: NES politika OID'li, yalnız {@code digitalSignature} taşıyan (NES'te
 * zorunlu {@code nonRepudiation} eksik) kendinden imzalı, güvenilir sertifika.</p>
 */
class AdvancedSignatureVerificationServiceKeyUsageVerdictTest {

    private static final String NES_POLICY_OID = "2.16.792.1.2.1.1.5.7.1.1";
    private static final String CONTENT = "<Invoice><ID>1</ID><Note>Orijinal</Note></Invoice>";

    private static KeyPair keys;
    private static X509Certificate nesWithoutNonRepudiation;

    @BeforeAll
    static void createSigner() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keys = generator.generateKeyPair();
        X500Name name = new X500Name("CN=NES KeyUsage Test");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.TEN,
                new Date(System.currentTimeMillis() - 3600000), new Date(System.currentTimeMillis() + 86400000),
                name, keys.getPublic());
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        builder.addExtension(Extension.certificatePolicies, false,
                new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(NES_POLICY_OID))));
        nesWithoutNonRepudiation = new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())));
    }

    @Test
    void dssPassedSignature_profileViolationMakesItIndeterminate() throws Exception {
        byte[] signed = xadesEnveloped();

        SignatureInfo dssOnly = verify(signed, false);
        SignatureInfo gated = verify(signed, true);

        assertEquals("TOTAL_PASSED", dssOnly.getIndication(), "Ön koşul: DSS imzayı geçirmeli");
        assertFalse(gated.isValid());
        assertEquals("INDETERMINATE", gated.getIndication());
        assertEquals("CHAIN_CONSTRAINTS_FAILURE", gated.getSubIndication());
        assertEquals("TOTAL_PASSED", keyUsageRejection(gated).getOriginalIndication());
    }

    @Test
    void dssTotalFailed_keepsDssVerdictAndErrors() throws Exception {
        byte[] tampered = new String(xadesEnveloped(), StandardCharsets.UTF_8)
                .replace("Orijinal", "Degisti").getBytes(StandardCharsets.UTF_8);

        SignatureInfo dssOnly = verify(tampered, false);
        SignatureInfo gated = verify(tampered, true);

        assertEquals("TOTAL_FAILED", dssOnly.getIndication(), "Ön koşul: kurcalanmış belge DSS'te TOTAL_FAILED");
        assertKeepsDssVerdict(dssOnly, gated);
    }

    @Test
    void dssSigConstraintsFailure_keepsDssCriticalErrorLine() throws Exception {
        byte[] plainXmlDsig = xmlDsigEnveloped();

        SignatureInfo dssOnly = verify(plainXmlDsig, false);
        SignatureInfo gated = verify(plainXmlDsig, true);

        assertEquals("SIG_CONSTRAINTS_FAILURE", dssOnly.getSubIndication(),
                "Ön koşul: XAdES özellikleri olmayan imza DSS'te SIG_CONSTRAINTS_FAILURE");
        assertKeepsDssVerdict(dssOnly, gated);
    }

    /** DSS reddettiyse kontrol kararı değiştirmez, DSS'in hata satırlarını silmez; ihlali ekler. */
    private static void assertKeepsDssVerdict(SignatureInfo dssOnly, SignatureInfo gated) {
        assertFalse(gated.isValid());
        assertEquals(dssOnly.getIndication(), gated.getIndication(), "DSS indication korunmalı");
        assertEquals(dssOnly.getSubIndication(), gated.getSubIndication(), "DSS subIndication korunmalı");
        assertTrue(gated.getValidationErrors().containsAll(dssOnly.getValidationErrors()),
                "DSS hata satırları korunmalı. DSS: " + dssOnly.getValidationErrors()
                        + " / kontrol açık: " + gated.getValidationErrors());
        assertEquals(dssOnly.getIndication(), keyUsageRejection(gated).getOriginalIndication());
    }

    private static AppliedRejection keyUsageRejection(SignatureInfo signature) {
        assertNotNull(signature.getAppliedRejections(), "Profil ihlali appliedRejections'a yazılmalı");
        for (AppliedRejection rejection : signature.getAppliedRejections()) {
            if ("MDSS-TR-KEYUSAGE-PROFILE".equals(rejection.getCode())) {
                return rejection;
            }
        }
        throw new AssertionError("MDSS-TR-KEYUSAGE-PROFILE yok: " + signature.getAppliedRejections());
    }

    private static SignatureInfo verify(byte[] signed, boolean keyUsageProfileEnabled) {
        AdvancedSignatureVerificationService service = new AdvancedSignatureVerificationService();
        VerificationConfiguration config = new VerificationConfiguration();
        ReflectionTestUtils.setField(config, "signerKeyUsageProfileEnabled", keyUsageProfileEnabled);
        ReflectionTestUtils.setField(service, "config", config);
        ReflectionTestUtils.setField(service, "resourceLoader", new DefaultResourceLoader());
        ReflectionTestUtils.setField(service, "dssValidationLocale", Locale.ENGLISH);
        ReflectionTestUtils.setField(service, "xadesPackagingDetector", new XadesSignaturePackagingDetector());
        ReflectionTestUtils.setField(service, "legacyTrXadesDetector", new LegacyTurkishXadesTypeUriDetector());
        ReflectionTestUtils.setField(service, "revocationInfoExtractor", new RevocationInfoExtractor());
        ReflectionTestUtils.setField(service, "rootCertificateService",
                org.mockito.Mockito.mock(KamusmRootCertificateService.class));
        RequestTrustContext trust = new RequestTrustContext("CUSTOM",
                Collections.singletonList(new CertificateToken(nesWithoutNonRepudiation)));
        MockMultipartFile file = new MockMultipartFile("signedDocument", "invoice.xml", "text/xml", signed);
        return service.verifySignature(file, null, VerificationLevel.SIMPLE, false, trust).getSignatures().get(0);
    }

    /** DSS ile XAdES-BASELINE-B enveloped imza (imza değeri JCA ile). */
    private static byte[] xadesEnveloped() throws Exception {
        XAdESService service = new XAdESService(new CommonCertificateVerifier());
        XAdESSignatureParameters parameters = new XAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        parameters.setSignaturePackaging(eu.europa.esig.dss.enumerations.SignaturePackaging.ENVELOPED);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(new CertificateToken(nesWithoutNonRepudiation));
        DSSDocument document = new InMemoryDocument(CONTENT.getBytes(StandardCharsets.UTF_8), "invoice.xml");
        ToBeSigned toBeSigned = service.getDataToSign(document, parameters);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keys.getPrivate());
        signer.update(toBeSigned.getBytes());
        SignatureValue value = new SignatureValue(SignatureAlgorithm.RSA_SHA256, signer.sign());
        return DSSUtils.toByteArray(service.signDocument(document, parameters, value));
    }

    /** XAdES özellikleri (SigningTime, SigningCertificate) olmayan düz XMLDSig enveloped imza. */
    private static byte[] xmlDsigEnveloped() throws Exception {
        DocumentBuilderFactory documents = DocumentBuilderFactory.newInstance();
        documents.setNamespaceAware(true);
        Document document = documents.newDocumentBuilder().newDocument();
        Element root = document.createElement("Invoice");
        root.setTextContent("Orijinal");
        document.appendChild(root);
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        KeyInfo keyInfo = factory.getKeyInfoFactory().newKeyInfo(Collections.singletonList(
                factory.getKeyInfoFactory().newX509Data(Collections.singletonList(nesWithoutNonRepudiation))));
        Reference reference = factory.newReference("", factory.newDigestMethod(DigestMethod.SHA256, null),
                Collections.singletonList(factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null)),
                null, null);
        SignedInfo signedInfo = factory.newSignedInfo(
                factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                factory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                Collections.singletonList(reference));
        DOMSignContext context = new DOMSignContext(keys.getPrivate(), root);
        context.setDefaultNamespacePrefix("ds");
        factory.newXMLSignature(signedInfo, keyInfo, null, "plain-signature", null).sign(context);
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(output));
        return output.toByteArray();
    }
}
