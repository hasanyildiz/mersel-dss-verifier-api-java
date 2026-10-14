package io.mersel.dss.verify.api.services.compliance;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SubIndication;
import io.mersel.dss.verify.api.models.enums.RejectionCode;
import io.mersel.dss.verify.api.services.compliance.ValidationDataChecker.CertNode;
import io.mersel.dss.verify.api.services.compliance.ValidationDataChecker.RefMatch;
import io.mersel.dss.verify.api.services.compliance.ValidationDataChecker.RevNode;
import io.mersel.dss.verify.api.services.compliance.ValidationDataChecker.RevocationOutcome;
import io.mersel.dss.verify.api.services.compliance.ValidationDataChecker.Role;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Sıkı referans kuralları — TÜBİTAK ES-XL örneklerindeki (ESXL1_MM_27..60) doğrulama verisi
 * yapıları modelle kurulur. Kontrol zamanı T: imza zaman damgası.
 */
class ValidationDataCheckerTest {

    private static final long HOUR = 60L * 60 * 1000;
    private static final long DAY = 24 * HOUR;
    private static final Date T = new Date(1672909200000L); // 05.01.2023 09:00 UTC

    private static KeyPair caKeys;
    private static KeyPair otherKeys;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        caKeys = generator.generateKeyPair();
        otherKeys = generator.generateKeyPair();
    }

    // ------------------------------------------------------------ güven kökü

    @Test
    void forgedTrustAnchorIsRejected() { // ESXL1_MM_36 / _53
        CertNode root = cert("CN=Root B", true, true, false);
        TrComplianceFinding finding = ValidationDataChecker.checkTrustAnchor(
                Arrays.asList(cert("CN=QC B", false, false, true), root), "İmzacı sertifika zincirinin");
        assertNotNull(finding);
        assertEquals(RejectionCode.MDSS_TR_TRUST_ANCHOR_SIGNATURE_INVALID, finding.getCode());
        assertTrue(finding.getReason().contains("CN=Root B"));
    }

    @Test
    void intactTrustAnchorPasses() {
        assertNull(ValidationDataChecker.checkTrustAnchor(
                Arrays.asList(cert("CN=QC A", false, false, true), cert("CN=Root A", true, true, true)), "x"));
    }

    // ------------------------------------------------------------ sertifika referansları

    @Test
    void missingRootReferenceIsReported() { // ESXL1_MM_57
        List<CertNode> chain = chain();
        Map<String, List<RefMatch>> refs = new HashMap<>();
        refs.put("SUB", Collections.singletonList(new RefMatch(true, true)));
        List<TrComplianceFinding> findings = ValidationDataChecker.checkCertificateRefs(chain, refs,
                "Kök sertifikası", "Alt kök sertifikası");
        assertEquals(1, findings.size());
        assertEquals(RejectionCode.MDSS_TR_CERT_REF_MISSING, findings.get(0).getCode());
        assertTrue(findings.get(0).getReason().startsWith("Kök sertifikası ('CN=Root A')"));
        assertTrue(findings.get(0).getReason().contains("Eksik bilginin tamamlanması gerekmektedir"));
    }

    @Test
    void missingIntermediateReferenceIsReported() { // ESXL1_MM_59
        Map<String, List<RefMatch>> refs = new HashMap<>();
        refs.put("ROOT", Collections.singletonList(new RefMatch(true, true)));
        List<TrComplianceFinding> findings = ValidationDataChecker.checkCertificateRefs(chain(), refs,
                "Kök sertifikası", "Alt kök sertifikası");
        assertEquals(1, findings.size());
        assertTrue(findings.get(0).getReason().startsWith("Alt kök sertifikası ('CN=SubRoot A1')"));
    }

    @Test
    void wrongReferenceDigestIsReported() { // ESXL1_MM_58 / _60
        Map<String, List<RefMatch>> refs = new HashMap<>();
        refs.put("SUB", Collections.singletonList(new RefMatch(true, true)));
        refs.put("ROOT", Collections.singletonList(new RefMatch(true, false)));
        List<TrComplianceFinding> findings = ValidationDataChecker.checkCertificateRefs(chain(), refs,
                "Kök sertifikası", "Alt kök sertifikası");
        assertEquals(1, findings.size());
        assertEquals(RejectionCode.MDSS_TR_CERT_REF_INVALID, findings.get(0).getCode());
        assertTrue(findings.get(0).getReason().contains("hatalı"));
    }

    @Test
    void completeReferencesPass() { // ESXL1_MM_1
        Map<String, List<RefMatch>> refs = new HashMap<>();
        refs.put("SUB", Collections.singletonList(new RefMatch(true, true)));
        refs.put("ROOT", Collections.singletonList(new RefMatch(true, true)));
        assertTrue(ValidationDataChecker.checkCertificateRefs(chain(), refs, "Kök sertifikası",
                "Alt kök sertifikası").isEmpty());
    }

    // ------------------------------------------------------------ sertifika / iptal değerleri

    @Test
    void rootMissingFromCertificateValuesIsReported() { // ESXL1_MM_79 (_81: alt kök)
        List<TrComplianceFinding> findings = ValidationDataChecker.checkCertificateValues(chain(),
                new java.util.HashSet<>(Collections.singletonList("SUB")));
        assertEquals(1, findings.size());
        assertEquals(RejectionCode.MDSS_TR_CERT_VALUE_MISSING, findings.get(0).getCode());
        assertTrue(findings.get(0).getReason().startsWith("Kök sertifikası ('CN=Root A')"));
    }

    @Test
    void completeCertificateValuesPass() {
        assertTrue(ValidationDataChecker.checkCertificateValues(chain(),
                new java.util.HashSet<>(Arrays.asList("SUB", "ROOT"))).isEmpty());
    }

    @Test
    void revocationValueWithoutReferenceIsMissing() { // ESXL1_MM_61 / _63 / _65 / _67
        ValidationDataChecker.RevocationRefs refs = new ValidationDataChecker.RevocationRefs();
        refs.present = true;
        refs.unreferencedValues.add("SİL ('Root A', 30.05.2019 13:00:00)");
        TrComplianceFinding finding = ValidationDataChecker.checkRevocationRefs(refs);
        assertEquals(RejectionCode.MDSS_TR_REVOCATION_REF_MISSING, finding.getCode());
        assertTrue(finding.getReason().contains("Eksik bilginin tamamlanması gerekmektedir"));
    }

    @Test
    void revocationReferenceWithWrongDigestIsInvalid() { // ESXL1_MM_62 / _64 / _66 / _68, _84 / _88 / _90
        ValidationDataChecker.RevocationRefs refs = new ValidationDataChecker.RevocationRefs();
        refs.present = true;
        refs.unreferencedValues.add("OCSP cevabı ('OCSP A1', 05.01.2023 12:01:20)");
        refs.valuelessReferences.add("OCSP cevabı");
        assertEquals(RejectionCode.MDSS_TR_REVOCATION_REF_INVALID,
                ValidationDataChecker.checkRevocationRefs(refs).getCode());
    }

    @Test
    void referenceWithoutRevocationValueIsMissingData() { // ESXL1_MM_83 / _85 / _87 / _89
        ValidationDataChecker.RevocationRefs refs = new ValidationDataChecker.RevocationRefs();
        refs.present = true;
        refs.valuelessReferences.add("SİL ('Root A', 30.05.2019 13:00:00)");
        TrComplianceFinding finding = ValidationDataChecker.checkRevocationRefs(refs);
        assertEquals(RejectionCode.MDSS_TR_REVOCATION_DATA_MISSING, finding.getCode());
        assertTrue(finding.getReason().startsWith("İptal değeri eksik"));
    }

    @Test
    void matchingRevocationReferencesPass() {
        ValidationDataChecker.RevocationRefs refs = new ValidationDataChecker.RevocationRefs();
        refs.present = true;
        assertNull(ValidationDataChecker.checkRevocationRefs(refs));
        assertNull(ValidationDataChecker.checkRevocationRefs(new ValidationDataChecker.RevocationRefs()));
    }

    // ------------------------------------------------------------ iptal verisi

    @Test
    void caRevokedBeforeControlTimeIsRejected() { // ESXL1_MM_27 (SİL) / _30 (OCSP)
        CertNode subRoot = subRoot(crl(true, T.getTime() - 4 * 365 * DAY, T.getTime() + 365 * DAY,
                CertificateStatus.REVOKED, new Date(T.getTime() - 3 * 365 * DAY)));
        RevocationOutcome outcome = evaluate(subRoot, Role.CA, true);
        assertEquals(RejectionCode.MDSS_TR_CERT_REVOKED, outcome.finding.getCode());
        assertEquals(SubIndication.REVOKED_CA_NO_POE, outcome.finding.getSubIndication());
        assertTrue(outcome.finding.getReason().startsWith("Alt kök sertifikası"));
    }

    @Test
    void caRevokedAfterControlTimeIsValidButNeedsArchiving() { // ESXL1_MM_44 / _45
        CertNode subRoot = subRoot(crl(true, T.getTime() - DAY, T.getTime() + 365 * DAY,
                CertificateStatus.REVOKED, new Date(T.getTime() + HOUR)));
        RevocationOutcome outcome = evaluate(subRoot, Role.CA, true);
        assertNull(outcome.finding);
        assertEquals(1, outcome.laterRevocations.size());
        assertEquals("CN=SubRoot A1", outcome.laterRevocations.get(0).getSubject());
    }

    @Test
    void signerRevokedAfterControlTimeIsNotAnArchiveReason() { // ESXL1_MM_41 / _42
        CertNode signer = subRoot(crl(true, T.getTime() - DAY, T.getTime() + 365 * DAY,
                CertificateStatus.REVOKED, new Date(T.getTime() + HOUR)));
        RevocationOutcome outcome = evaluate(signer, Role.SIGNER, true);
        assertNull(outcome.finding);
        assertTrue(outcome.laterRevocations.isEmpty());
    }

    @Test
    void expiredReferencedCrlIsRejectedEvenIfOtherDataIsFresh() { // ESXL1_MM_28
        CertNode subRoot = subRoot(crl(true, T.getTime() - 300 * DAY, T.getTime() - 250 * DAY,
                CertificateStatus.GOOD, null));
        // Zaman damgası içindeki geçerli SİL referans verilmiş değil (DSS bunu kullanıyordu).
        subRoot.revocations.add(crl(false, T.getTime() - DAY, T.getTime() + 365 * DAY, CertificateStatus.GOOD, null));
        RevocationOutcome outcome = evaluate(subRoot, Role.CA, true);
        assertEquals(RejectionCode.MDSS_TR_CRL_EXPIRED, outcome.finding.getCode());
    }

    @Test
    void forgedReferencedOcspIsRejected() { // ESXL1_MM_32
        CertNode subRoot = subRoot(ocsp(false, T.getTime() + 2000, null, CertificateStatus.GOOD, responder()));
        assertEquals(RejectionCode.MDSS_TR_REVOCATION_SIGNATURE_INVALID, evaluate(subRoot, Role.CA, true).finding.getCode());
    }

    @Test
    void staleOcspResponseIsRejected() { // ESXL1_MM_31 (2012 tarihli cevap)
        CertNode subRoot = subRoot(ocsp(true, T.getTime() - 11 * 365 * DAY, null, CertificateStatus.GOOD, responder()));
        RevocationOutcome outcome = evaluate(subRoot, Role.CA, true);
        assertEquals(RejectionCode.MDSS_TR_OCSP_EXPIRED, outcome.finding.getCode());
    }

    @Test
    void ocspProducedSecondsBeforeTimestampIsFresh() { // KRİPTO_SUİT: thisUpdate damgadan ~1 sn önce
        CertNode signer = subRoot(ocsp(true, T.getTime() - 1000, null, CertificateStatus.GOOD, responder()));
        assertNull(evaluate(signer, Role.SIGNER, true).finding);
    }

    @Test
    void expiredOcspResponderIsRejected() { // ESXL1_MM_33
        CertNode expired = new CertNode("OCSP", "CN=OCSP A4", new Date(T.getTime() - 4 * 365 * DAY),
                new Date(T.getTime() - 3 * 365 * DAY), false, false, true, false);
        CertNode subRoot = subRoot(ocsp(true, T.getTime() + 2000, null, CertificateStatus.GOOD, expired));
        RevocationOutcome outcome = evaluate(subRoot, Role.CA, true);
        assertEquals(RejectionCode.MDSS_TR_OCSP_RESPONDER_INVALID, outcome.finding.getCode());
        assertTrue(outcome.finding.getReason().contains("geçerli değil"));
    }

    @Test
    void forgedOcspResponderCertificateIsRejected() { // ESXL1_MM_34
        CertNode forged = new CertNode("OCSP", "CN=OCSP A5", new Date(T.getTime() - 365 * DAY),
                new Date(T.getTime() + 365 * DAY), false, false, false, false);
        CertNode subRoot = subRoot(ocsp(true, T.getTime() + 2000, null, CertificateStatus.GOOD, forged));
        assertEquals(RejectionCode.MDSS_TR_OCSP_RESPONDER_INVALID, evaluate(subRoot, Role.CA, true).finding.getCode());
    }

    @Test
    void revokedOcspResponderIsRejectedEvenWithAValidCrl() { // ESXL1_MM_35
        CertNode revokedResponder = responder();
        revokedResponder.revocations.add(crl(true, T.getTime() - DAY, T.getTime() + 365 * DAY,
                CertificateStatus.REVOKED, new Date(T.getTime() - 365 * DAY)));
        CertNode subRoot = subRoot(ocsp(true, T.getTime() + 2000, null, CertificateStatus.GOOD, revokedResponder));
        subRoot.revocations.add(crl(true, T.getTime() - DAY, T.getTime() + 365 * DAY, CertificateStatus.GOOD, null));
        RevocationOutcome outcome = evaluate(subRoot, Role.CA, true);
        assertEquals(RejectionCode.MDSS_TR_OCSP_RESPONDER_INVALID, outcome.finding.getCode());
        assertTrue(outcome.finding.getReason().contains("iptal"));
    }

    @Test
    void responderRevokedAfterResponseIsValidButNeedsArchiving() { // ESXL1_MM_43 / _46
        CertNode responder = responder();
        responder.revocations.add(crl(true, T.getTime() - DAY, T.getTime() + 365 * DAY,
                CertificateStatus.REVOKED, new Date(T.getTime() + HOUR)));
        CertNode subRoot = subRoot(ocsp(true, T.getTime() + 2000, null, CertificateStatus.GOOD, responder));
        RevocationOutcome outcome = evaluate(subRoot, Role.CA, true);
        assertNull(outcome.finding);
        assertEquals(1, outcome.laterRevocations.size());
        assertEquals("CN=OCSP A1", outcome.laterRevocations.get(0).getSubject());
    }

    @Test
    void tsaChainAcceptsAnyValidReferencedData() { // ESXL1_MM_28: TSA, zaman damgası içindeki geçerli SİL'le
        CertNode tsa = subRoot(crl(true, T.getTime() - 300 * DAY, T.getTime() - 250 * DAY, CertificateStatus.GOOD, null));
        tsa.revocations.add(crl(true, T.getTime() - DAY, T.getTime() + 365 * DAY, CertificateStatus.GOOD, null));
        assertNull(evaluate(tsa, Role.TSA, false).finding);
        assertNotNull(evaluate(tsa, Role.CA, true).finding);
    }

    @Test
    void tsaRevokedBeforeTimestampIsRejected() { // ESXL1_MM_51
        CertNode tsa = subRoot(crl(true, T.getTime() - DAY, T.getTime() + 365 * DAY,
                CertificateStatus.REVOKED, new Date(T.getTime() - 365 * DAY)));
        RevocationOutcome outcome = evaluate(tsa, Role.TSA, false);
        assertEquals(RejectionCode.MDSS_TR_CERT_REVOKED, outcome.finding.getCode());
        assertTrue(outcome.finding.getReason().startsWith("Zaman damgası sertifikası"));
    }

    @Test
    void missingReferencedRevocationDataIsReported() { // ESXL1_MM_29 benzeri, bağlanamayan veri yok
        CertNode subRoot = subRoot(crl(false, T.getTime() - DAY, T.getTime() + 365 * DAY, CertificateStatus.GOOD, null));
        RevocationOutcome outcome = evaluate(subRoot, Role.CA, true);
        assertEquals(RejectionCode.MDSS_TR_REVOCATION_DATA_MISSING, outcome.finding.getCode());
        assertTrue(outcome.finding.getReason().contains("Eksik bilginin tamamlanması gerekmektedir"));
    }

    @Test
    void unverifiableCrlFromIssuerIsReportedAsForged() throws Exception { // ESXL1_MM_29
        X509Certificate issuer = certificate("CN=Root A", caKeys);
        X509CRL forged = crl("CN=Root A", otherKeys);
        CertNode subRoot = new CertNode("SUB", "CN=SubRoot A5", new Date(T.getTime() - 365 * DAY),
                new Date(T.getTime() + 365 * DAY), false, false, true, false);
        RevocationOutcome outcome = ValidationDataChecker.evaluateRevocation(subRoot, Role.CA, T, "imza zaman damgası",
                Collections.singletonList(forged), issuer, true, true);
        assertEquals(RejectionCode.MDSS_TR_REVOCATION_SIGNATURE_INVALID, outcome.finding.getCode());
    }

    @Test
    void responderWithoutRevocationDataIsAccepted() { // OCSP sertifikasının iptal verisi zorunlu değil
        assertNull(ValidationDataChecker.evaluateRevocation(responder(), Role.OCSP_RESPONDER, T, null,
                Collections.<X509CRL>emptyList(), null, false, true).finding);
    }

    // ------------------------------------------------------------ esnek mod (BES / ES-T)

    @Test
    void lenientModeRejectsOnlyExpiredCrls() { // ESXL1_MM_17, BES_28
        CertNode signer = subRoot(crl(true, T.getTime() - 300 * DAY, T.getTime() - 250 * DAY, CertificateStatus.GOOD, null));
        signer.revocations.add(crl(true, T.getTime() - 200 * DAY, T.getTime() - 100 * DAY, CertificateStatus.GOOD, null));
        assertEquals(RejectionCode.MDSS_TR_CRL_EXPIRED, lenient(signer, Role.SIGNER).finding.getCode());
    }

    @Test
    void lenientModeAcceptsAnyCoveringData() { // ESXL1_MM_1: kapsayan SİL veya OCSP cevabı
        CertNode signer = subRoot(crl(true, T.getTime() - 300 * DAY, T.getTime() - 250 * DAY, CertificateStatus.GOOD, null));
        signer.revocations.add(ocsp(true, T.getTime() + 2000, null, CertificateStatus.GOOD, responder()));
        assertNull(lenient(signer, Role.SIGNER).finding);
    }

    @Test
    void lenientModeLeavesMissingDataToDss() {
        assertNull(lenient(new CertNode("SUB", "CN=SubRoot A1", null, null, false, false, true, false), Role.CA).finding);
    }

    @Test
    void lenientModeStillRejectsCaRevokedBeforeControlTime() { // BES_27 / EST_27: çevrimiçi SİL'de iptal
        CertNode subRoot = subRoot(crl(true, T.getTime() - DAY, T.getTime() + 365 * DAY,
                CertificateStatus.REVOKED, new Date(T.getTime() - 365 * DAY)));
        assertEquals(RejectionCode.MDSS_TR_CERT_REVOKED, lenient(subRoot, Role.CA).finding.getCode());
    }

    @Test
    void ocspFreshnessUsesNextUpdateWhenPresent() {
        RevNode covered = ocsp(true, T.getTime() - 30 * DAY, new Date(T.getTime() + DAY), CertificateStatus.GOOD, null);
        RevNode expired = ocsp(true, T.getTime() - 30 * DAY, new Date(T.getTime() - DAY), CertificateStatus.GOOD, null);
        assertTrue(ValidationDataChecker.ocspCovers(covered, T));
        assertFalse(ValidationDataChecker.ocspCovers(expired, T));
    }

    // ------------------------------------------------------------ yardımcılar

    /** Sıkı mod (requireAll) veya TSA zinciri; iptal verisi zorunlu. */
    private static RevocationOutcome evaluate(CertNode certificate, Role role, boolean requireAll) {
        return ValidationDataChecker.evaluateRevocation(certificate, role, T, "imza zaman damgası",
                Collections.<X509CRL>emptyList(), null, requireAll, true);
    }

    /** Esnek mod (BES / ES-T): DSS'in bulduğu tüm veri, biri yeterli, veri yokluğu ret değil. */
    private static RevocationOutcome lenient(CertNode certificate, Role role) {
        return ValidationDataChecker.evaluateRevocation(certificate, role, T, "imza zaman damgası",
                Collections.<X509CRL>emptyList(), null, false, false);
    }

    private static List<CertNode> chain() {
        return Arrays.asList(new CertNode("LEAF", "CN=QC A1 1", null, null, false, false, true, false),
                new CertNode("SUB", "CN=SubRoot A1", null, null, false, false, true, false),
                new CertNode("ROOT", "CN=Root A", null, null, true, true, true, false));
    }

    private static CertNode cert(String subject, boolean trusted, boolean selfIssued, boolean intact) {
        return new CertNode(subject, subject, null, null, trusted, selfIssued, intact, false);
    }

    private static CertNode subRoot(RevNode revocation) {
        CertNode node = new CertNode("SUB", "CN=SubRoot A1", new Date(T.getTime() - 4 * 365 * DAY),
                new Date(T.getTime() + 6 * 365 * DAY), false, false, true, false);
        node.revocations.add(revocation);
        return node;
    }

    private static CertNode responder() {
        return new CertNode("OCSP", "CN=OCSP A1", new Date(T.getTime() - 4 * 365 * DAY),
                new Date(T.getTime() + 6 * 365 * DAY), false, false, true, false);
    }

    private static RevNode crl(boolean referenced, long thisUpdate, long nextUpdate, CertificateStatus status,
                               Date revocationDate) {
        return new RevNode("R-CRL-" + thisUpdate, RevocationType.CRL, referenced, new Date(thisUpdate),
                new Date(thisUpdate), new Date(nextUpdate), true, status, revocationDate, null);
    }

    private static RevNode ocsp(boolean intact, long thisUpdate, Date nextUpdate, CertificateStatus status,
                                CertNode responder) {
        return new RevNode("R-OCSP-" + thisUpdate, RevocationType.OCSP, true, new Date(thisUpdate + 1000),
                new Date(thisUpdate), nextUpdate, intact, status, null, responder);
    }

    private static X509Certificate certificate(String dn, KeyPair keys) throws Exception {
        X500Name name = new X500Name(dn);
        return new JcaX509CertificateConverter().getCertificate(new JcaX509v3CertificateBuilder(name,
                BigInteger.ONE, new Date(T.getTime() - 365 * DAY), new Date(T.getTime() + 365 * DAY), name,
                keys.getPublic()).build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate())));
    }

    private static X509CRL crl(String issuerDn, KeyPair signingKeys) throws Exception {
        X509v2CRLBuilder builder = new X509v2CRLBuilder(new X500Name(issuerDn), new Date(T.getTime() - DAY));
        builder.setNextUpdate(new Date(T.getTime() + 365 * DAY));
        return new JcaX509CRLConverter().getCRL(builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(signingKeys.getPrivate())));
    }
}
