package io.mersel.dss.verify.api.services.compliance;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import io.mersel.dss.verify.api.models.enums.RejectionCode;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * MA3 e-Fatura değerlendirme kuralları — ESXL1_MM_7..13 ve mali mühür MM_37..39
 * örneklerindeki sertifika yapıları yerel üretilen sertifikalarla.
 */
class TrComplianceCheckerTest {

    private static final String NES_POLICY = "2.16.792.1.2.1.1.5.7.1.1";
    private static final String QC_PKIX_SYNTAX_V2 = "1.3.6.1.5.5.7.11.1";
    private static final long DAY = 24L * 60 * 60 * 1000;

    private static KeyPair caKeys;
    private static KeyPair otherKeys;
    private static KeyPair leafKeys;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        caKeys = generator.generateKeyPair();
        otherKeys = generator.generateKeyPair();
        leafKeys = generator.generateKeyPair();
    }

    // ---------------------------------------------------------------- NES profili

    @Test
    void nesCertificateWithAllMa3Requirements_hasNoFindings() throws Exception {
        assertTrue(TrComplianceChecker.checkCertificateProfile(nes().build()).isEmpty());
    }

    @Test
    void nesWithoutNonRepudiation_isLeftToKeyUsageProfileCheck_likeMm7() throws Exception {
        // MM_7 MDSS-TR-KEYUSAGE-PROFILE ile bayraktan bağımsız reddedilir; burada
        // ikinci bir ret üretilmemeli.
        assertTrue(TrComplianceChecker.checkCertificateProfile(
                nes().keyUsage(KeyUsage.digitalSignature).build()).isEmpty());
    }

    @Test
    void nesPolicyWithoutUserNotice_isRejected_likeMm8() throws Exception {
        List<TrComplianceFinding> findings =
                TrComplianceChecker.checkCertificateProfile(nes().userNotice(false).build());

        assertCodes(findings, RejectionCode.MDSS_TR_NES_CERTIFICATE_POLICY);
        assertTrue(findings.get(0).getReason().contains(NES_POLICY));
        assertEquals(Indication.INDETERMINATE, findings.get(0).getIndication());
        assertEquals(SubIndication.CHAIN_CONSTRAINTS_FAILURE, findings.get(0).getSubIndication());
    }

    @Test
    void nesWithoutEtsiQcStatement_isRejected_likeMm9() throws Exception {
        assertCodes(TrComplianceChecker.checkCertificateProfile(
                        nes().qc(QC_PKIX_SYNTAX_V2, TrComplianceChecker.OID_QC_BTK).build()),
                RejectionCode.MDSS_TR_NES_QC_ETSI);
    }

    @Test
    void nesWithoutBtkQcStatement_isRejected_likeMm10() throws Exception {
        assertCodes(TrComplianceChecker.checkCertificateProfile(
                        nes().qc(QC_PKIX_SYNTAX_V2, TrComplianceChecker.OID_QC_ETSI_COMPLIANCE).build()),
                RejectionCode.MDSS_TR_NES_QC_BTK);
    }

    // ---------------------------------------------------------- mali mühür profili

    @Test
    void sealCertificate_isNotHeldToNesRules_likeMm37() throws Exception {
        X509Certificate seal = seal().build();
        assertTrue(TrComplianceChecker.checkCertificateProfile(seal).isEmpty(),
                "Mali mühür: yalnız digitalSignature, QC yok, UserNotice yok — geçerli");
    }

    @Test
    void sealWithoutExtendedKeyUsage_isRejected_likeMm38() throws Exception {
        assertCodes(TrComplianceChecker.checkCertificateProfile(seal().eku(null).build()),
                RejectionCode.MDSS_TR_SEAL_EXTENDED_KEY_USAGE);
    }

    @Test
    void sealWithNesPolicyInsteadOfSealPolicy_isRejected_likeMm39() throws Exception {
        assertCodes(TrComplianceChecker.checkCertificateProfile(seal().policy(NES_POLICY).build()),
                RejectionCode.MDSS_TR_SEAL_CERTIFICATE_POLICY);
    }

    // ------------------------------------------------------------------ ayrık imza

    @Test
    void detachedReference_withoutOriginalDocument_isRejected_likeMm11() {
        TrComplianceFinding finding = TrComplianceChecker.checkDetached(
                Collections.singletonList("./enveloped-content.xml"), false,
                Collections.singletonList(matcher("./enveloped-content.xml", false, false)));

        assertNotNull(finding);
        assertEquals(RejectionCode.MDSS_TR_XADES_DETACHED, finding.getCode());
        assertEquals(Indication.INDETERMINATE, finding.getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, finding.getSubIndication());
        assertTrue(finding.getReason().contains("özgün belge (originalDocument) gönderilmedi"));
        assertTrue(finding.getReason().contains("./enveloped-content.xml"));
        assertEquals(Boolean.FALSE, finding.getEvidence().get("originalDocumentProvided"));
        assertNull(TrComplianceChecker.checkDetached(Collections.<String>emptyList(), false, null));
    }

    @Test
    void detachedReference_verifiedByOriginalDocument_isAccepted() {
        // DSS referans URI'sini decode ederek saklar ("my%20invoice.xml" → "my invoice.xml").
        assertNull(TrComplianceChecker.checkDetached(
                Arrays.asList("my%20invoice.xml", "attachment.pdf"), true,
                Arrays.asList(matcher("my invoice.xml", true, true),
                        matcher("attachment.pdf", true, true),
                        matcher(null, true, true))));
    }

    @Test
    void detachedReference_notResolvedByOriginalDocument_isRejected() {
        TrComplianceFinding finding = TrComplianceChecker.checkDetached(
                Arrays.asList("invoice.xml", "attachment.pdf"), true,
                Arrays.asList(matcher("invoice.xml", true, true), matcher("attachment.pdf", false, false)));

        assertNotNull(finding);
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, finding.getSubIndication());
        assertTrue(finding.getReason().contains("attachment.pdf"));
        assertEquals(Collections.singletonList("attachment.pdf"),
                finding.getEvidence().get("unresolvedReferenceUris"));
    }

    @Test
    void detachedReference_withoutAnyDigestMatcher_isRejected() {
        TrComplianceFinding finding = TrComplianceChecker.checkDetached(
                Collections.singletonList("invoice.xml"), true, Collections.<XmlDigestMatcher>emptyList());

        assertNotNull(finding);
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, finding.getSubIndication());
    }

    @Test
    void detachedReference_digestMismatchWithOriginalDocument_isRejected() {
        TrComplianceFinding finding = TrComplianceChecker.checkDetached(
                Collections.singletonList("invoice.xml"), true,
                Collections.singletonList(matcher("invoice.xml", true, false)));

        assertNotNull(finding);
        assertEquals(Indication.TOTAL_FAILED, finding.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, finding.getSubIndication());
        assertEquals(Collections.singletonList("invoice.xml"),
                finding.getEvidence().get("digestMismatchReferenceUris"));
    }

    private static XmlDigestMatcher matcher(String uri, boolean found, boolean intact) {
        XmlDigestMatcher matcher = new XmlDigestMatcher();
        matcher.setType(DigestMatcherType.REFERENCE);
        matcher.setUri(uri);
        matcher.setDataFound(found);
        matcher.setDataIntact(intact);
        return matcher;
    }

    // --------------------------------------------------------- sertifika imzası

    @Test
    void certificateNotSignedByAnyIssuerWithItsName_isForged_likeMm13() throws Exception {
        X509Certificate genuineCa = ca(caKeys);
        X509Certificate leaf = nes().signedBy(otherKeys).build();

        TrComplianceFinding finding = TrComplianceChecker.checkIssuerSignature(
                leaf, true, Collections.singletonList(genuineCa));

        assertNotNull(finding);
        assertEquals(RejectionCode.MDSS_TR_CERT_SIGNATURE_INVALID, finding.getCode());
        assertTrue(finding.getReason().startsWith("İmzacı sertifikasının imzası"));
        assertTrue(finding.getReason().contains("CN=SubRoot A1"));
    }

    @Test
    void certificateSignedByCandidateIssuer_orWithoutCandidate_hasNoFinding() throws Exception {
        X509Certificate leaf = nes().build();
        assertNull(TrComplianceChecker.checkIssuerSignature(leaf, true,
                Arrays.asList(ca(otherKeys), ca(caKeys))));
        assertNull(TrComplianceChecker.checkIssuerSignature(leaf, true,
                Collections.<X509Certificate>emptyList()),
                "Düzenleyici hiç bulunamadıysa karar DSS'in 'zincir bulunamadı' sonucudur");
    }

    // ----------------------------------------------------- imza zamanı geçerliliği

    @Test
    void signatureTimestampAfterCertificateExpiry_isRejected_likeMm12() {
        Date notBefore = new Date(0);
        Date notAfter = new Date(100 * DAY);
        TrComplianceFinding finding = TrComplianceChecker.checkValidityAtSigningTime(
                notBefore, notAfter, new Date(200 * DAY), TrComplianceChecker.TIME_SOURCE_SIGNATURE_TIMESTAMP);

        assertNotNull(finding);
        assertEquals(RejectionCode.MDSS_TR_CERT_EXPIRED_AT_SIGNING_TIME, finding.getCode());
        assertTrue(finding.getReason().contains("süresi imza zamanından önce dolmuş"));
        assertTrue(finding.getReason().contains("imza zaman damgası"));
    }

    @Test
    void signingTimeInsideOrBeforeValidity() {
        Date notBefore = new Date(100 * DAY);
        Date notAfter = new Date(200 * DAY);
        assertNull(TrComplianceChecker.checkValidityAtSigningTime(notBefore, notAfter, new Date(150 * DAY), "x"));
        assertNull(TrComplianceChecker.checkValidityAtSigningTime(notBefore, notAfter, null, "x"));
        assertEquals(RejectionCode.MDSS_TR_CERT_NOT_YET_VALID_AT_SIGNING_TIME,
                TrComplianceChecker.checkValidityAtSigningTime(notBefore, notAfter, new Date(50 * DAY), "x").getCode());
    }

    // ------------------------------------------------------------------ yardımcılar

    private static void assertCodes(List<TrComplianceFinding> findings, RejectionCode... expected) {
        List<RejectionCode> codes = new ArrayList<>();
        for (TrComplianceFinding finding : findings) {
            codes.add(finding.getCode());
        }
        assertEquals(Arrays.asList(expected), codes);
    }

    private static X509Certificate ca(KeyPair keys) throws Exception {
        X500Name name = new X500Name("CN=SubRoot A1,O=Valid,C=TR");
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.TEN,
                new Date(System.currentTimeMillis() - DAY), new Date(System.currentTimeMillis() + DAY),
                name, keys.getPublic());
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        return new JcaX509CertificateConverter().getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())));
    }

    private static Leaf nes() {
        return new Leaf()
                .keyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation)
                .policy(NES_POLICY)
                .userNotice(true)
                .qc(QC_PKIX_SYNTAX_V2, TrComplianceChecker.OID_QC_ETSI_COMPLIANCE, TrComplianceChecker.OID_QC_BTK);
    }

    private static Leaf seal() {
        return new Leaf()
                .keyUsage(KeyUsage.digitalSignature)
                .policy(TrComplianceChecker.OID_SEAL_POLICY)
                .userNotice(false)
                .eku(TrComplianceChecker.OID_SEAL_EKU)
                .qc();
    }

    /** İmzacı sertifikası kurucusu; varsayılan düzenleyici "CN=SubRoot A1" ({@link #caKeys}). */
    private static final class Leaf {
        private int keyUsage;
        private String policy;
        private boolean userNotice;
        private String eku;
        private String[] qc = new String[0];
        private KeyPair issuerKeys = caKeys;

        Leaf keyUsage(int value) { keyUsage = value; return this; }
        Leaf policy(String value) { policy = value; return this; }
        Leaf userNotice(boolean value) { userNotice = value; return this; }
        Leaf eku(String value) { eku = value; return this; }
        Leaf qc(String... values) { qc = values; return this; }
        Leaf signedBy(KeyPair value) { issuerKeys = value; return this; }

        X509Certificate build() throws Exception {
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new X500Name("CN=SubRoot A1,O=Valid,C=TR"), BigInteger.ONE,
                    new Date(System.currentTimeMillis() - DAY), new Date(System.currentTimeMillis() + DAY),
                    new X500Name("CN=QC A1 1,O=Valid,C=TR"), leafKeys.getPublic());
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
            if (policy != null) {
                PolicyInformation information = userNotice
                        ? new PolicyInformation(new ASN1ObjectIdentifier(policy), new DERSequence(
                                new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, new UserNotice(null,
                                        new DisplayText("Bu sertifika, 5070 sayılı Elektronik İmza Kanununa "
                                                + "göre nitelikli elektronik sertifikadır.")))))
                        : new PolicyInformation(new ASN1ObjectIdentifier(policy));
                builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(information));
            }
            if (eku != null) {
                builder.addExtension(Extension.extendedKeyUsage, false,
                        new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(eku))));
            }
            if (qc.length > 0) {
                ASN1EncodableVector statements = new ASN1EncodableVector();
                for (String id : qc) {
                    statements.add(new QCStatement(new ASN1ObjectIdentifier(id)));
                }
                builder.addExtension(Extension.qCStatements, false, new DERSequence(statements));
            }
            return new JcaX509CertificateConverter().getCertificate(
                    builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKeys.getPrivate())));
        }
    }
}
