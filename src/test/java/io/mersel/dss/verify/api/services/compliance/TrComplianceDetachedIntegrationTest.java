package io.mersel.dss.verify.api.services.compliance;

import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import io.mersel.dss.verify.api.models.enums.RejectionCode;
import io.mersel.dss.verify.api.services.util.XadesSignaturePackagingDetector;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.OctetStreamData;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Ayrık imza kuralı gerçek DSS diagnostic verisiyle: referans URI'si DSS'te decode
 * edilir, özgün belge {@code originalDocument} olarak verilmezse veya eşleşmezse ret,
 * eşleşirse kural sessiz kalır. Ağ kaynağı kullanılmaz.
 */
class TrComplianceDetachedIntegrationTest {

    private static final String REFERENCE_URI = "my%20invoice.xml";
    private static final byte[] CONTENT = "<Invoice>offline detached test</Invoice>".getBytes(StandardCharsets.UTF_8);

    private static X509Certificate certificate;
    private static byte[] detachedSignature;

    @BeforeAll
    static void signDetached() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        X500Name name = new X500Name("CN=Local Detached Signature Test");
        certificate = new JcaX509CertificateConverter().getCertificate(
                new JcaX509v3CertificateBuilder(name, BigInteger.ONE, new Date(System.currentTimeMillis() - 60000),
                        new Date(System.currentTimeMillis() + 86400000), name, keys.getPublic())
                        .build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())));

        DocumentBuilderFactory documents = DocumentBuilderFactory.newInstance();
        documents.setNamespaceAware(true);
        Document document = documents.newDocumentBuilder().newDocument();
        Element root = document.createElement("DetachedSignatures");
        document.appendChild(root);

        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");
        KeyInfo keyInfo = factory.getKeyInfoFactory().newKeyInfo(Collections.singletonList(
                factory.getKeyInfoFactory().newX509Data(Collections.singletonList(certificate))));
        Reference reference = factory.newReference(REFERENCE_URI,
                factory.newDigestMethod(DigestMethod.SHA256, null), null, null, "detached-ref");
        SignedInfo signedInfo = factory.newSignedInfo(
                factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null),
                factory.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                Collections.singletonList(reference));
        DOMSignContext context = new DOMSignContext(keys.getPrivate(), root);
        context.setDefaultNamespacePrefix("ds");
        context.setURIDereferencer((uriReference, ctx) -> new OctetStreamData(new ByteArrayInputStream(CONTENT)));
        factory.newXMLSignature(signedInfo, keyInfo, null, "detached-signature", null).sign(context);

        ByteArrayOutputStream output = new ByteArrayOutputStream();
        TransformerFactory.newInstance().newTransformer().transform(new DOMSource(document), new StreamResult(output));
        detachedSignature = output.toByteArray();
    }

    @Test
    void withoutOriginalDocument_isRejected() {
        Validation validation = validate(null);

        assertEquals(Collections.singletonList(REFERENCE_URI), validation.externalUris);
        TrComplianceFinding finding = validation.detachedFinding(false);
        assertNotNull(finding);
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, finding.getSubIndication());
        assertNotNull(validation.detachedFindingViaEvaluate(false));
    }

    @Test
    void withMatchingOriginalDocument_isAccepted() {
        Validation validation = validate(new InMemoryDocument(CONTENT, "my invoice.xml"));

        assertTrue(validation.wrapper.isSignatureIntact(), "Yerel imza kriptografik olarak sağlam olmalı");
        XmlDigestMatcher matcher = validation.referenceMatcher();
        assertEquals("my invoice.xml", matcher.getUri(), "DSS referans URI'sini decode ederek saklar");
        assertTrue(matcher.isDataFound());
        assertTrue(matcher.isDataIntact());
        assertNull(validation.detachedFinding(true));
        assertNull(validation.detachedFindingViaEvaluate(true));
    }

    @Test
    void withModifiedOriginalDocument_isRejected() {
        Validation validation = validate(new InMemoryDocument(
                "<Invoice>tampered</Invoice>".getBytes(StandardCharsets.UTF_8), "my invoice.xml"));

        TrComplianceFinding finding = validation.detachedFinding(true);
        assertNotNull(finding);
        assertEquals(Indication.TOTAL_FAILED, finding.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, finding.getSubIndication());
        assertNotNull(validation.detachedFindingViaEvaluate(true));
    }

    private static Validation validate(DSSDocument original) {
        CommonTrustedCertificateSource trust = new CommonTrustedCertificateSource();
        trust.addCertificate(new CertificateToken(certificate));
        CommonCertificateVerifier verifier = new CommonCertificateVerifier();
        verifier.setTrustedCertSources(trust);
        // No AIA, OCSP, CRL or network data loaders are configured.
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(
                new InMemoryDocument(detachedSignature, "detached.xml"));
        validator.setCertificateVerifier(verifier);
        if (original != null) {
            validator.setDetachedContents(Collections.singletonList(original));
        }
        Reports reports = validator.validateDocument();
        List<AdvancedSignature> signatures = validator.getSignatures();
        assertEquals(1, signatures.size());
        AdvancedSignature signature = signatures.get(0);
        return new Validation(reports.getDiagnosticData().getSignatureById(signature.getId()),
                new XadesSignaturePackagingDetector().externalReferenceUris(signature));
    }

    private static final class Validation {
        final SignatureWrapper wrapper;
        final List<String> externalUris;

        Validation(SignatureWrapper wrapper, List<String> externalUris) {
            this.wrapper = wrapper;
            this.externalUris = externalUris;
        }

        TrComplianceFinding detachedFinding(boolean originalDocumentProvided) {
            return TrComplianceChecker.checkDetached(externalUris, originalDocumentProvided,
                    wrapper.getDigestMatchers());
        }

        /** {@code evaluate} üzerinden: imzanın DSS özet eşleştiricileri kurala ulaşıyor mu. */
        TrComplianceFinding detachedFindingViaEvaluate(boolean originalDocumentProvided) {
            List<TrComplianceFinding> findings = new TrComplianceChecker().evaluate(wrapper,
                    new ArrayList<CertificateToken>(), externalUris, originalDocumentProvided, new Date(), null);
            for (TrComplianceFinding finding : findings) {
                if (finding.getCode() == RejectionCode.MDSS_TR_XADES_DETACHED) {
                    return finding;
                }
            }
            return null;
        }

        XmlDigestMatcher referenceMatcher() {
            for (XmlDigestMatcher matcher : wrapper.getDigestMatchers()) {
                if (matcher.getUri() != null && !matcher.getUri().startsWith("#")) {
                    return matcher;
                }
            }
            throw new AssertionError("Ayrık referansın özet eşleştiricisi bulunamadı: " + wrapper.getDigestMatchers());
        }
    }
}
