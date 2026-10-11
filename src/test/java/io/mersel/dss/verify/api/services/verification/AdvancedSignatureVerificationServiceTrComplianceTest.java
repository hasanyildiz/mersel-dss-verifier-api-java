package io.mersel.dss.verify.api.services.verification;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import io.mersel.dss.verify.api.models.AppliedRejection;
import io.mersel.dss.verify.api.models.FailedConstraint;
import io.mersel.dss.verify.api.models.FailureCategory;
import io.mersel.dss.verify.api.models.SignatureInfo;
import io.mersel.dss.verify.api.models.enums.RejectionCode;
import io.mersel.dss.verify.api.services.compliance.TrComplianceFinding;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

/** TR uyum bulgularının imza sonucuna yazılması (MDSS-TR-*). */
class AdvancedSignatureVerificationServiceTrComplianceTest {

    @Test
    void dssPassedSignature_isRejected_withTheFirstFindingAsRootCause() {
        SignatureInfo signature = signature(true, "TOTAL_PASSED", null);
        signature.setFailedConstraints(new ArrayList<FailedConstraint>());

        AdvancedSignatureVerificationService.applyTrFindings(signature, Arrays.asList(
                finding(RejectionCode.MDSS_TR_NES_CERTIFICATE_POLICY, "UserNotice yok"),
                finding(RejectionCode.MDSS_TR_NES_QC_BTK, "BTK OID'si yok")));

        assertFalse(signature.isValid());
        assertEquals("INDETERMINATE", signature.getIndication());
        assertEquals("CHAIN_CONSTRAINTS_FAILURE", signature.getSubIndication());
        assertEquals("MDSS-TR-NES-CERTIFICATE-POLICY", signature.getRootCause().getKey());
        assertEquals("UserNotice yok", signature.getRootCause().getMessage());
        assertEquals(FailureCategory.ROOT_CAUSE, signature.getRootCause().getCategory());
        assertEquals(Arrays.asList(
                "[MDSS-TR-NES-CERTIFICATE-POLICY] UserNotice yok",
                "[MDSS-TR-NES-QC-BTK] BTK OID'si yok"), signature.getValidationErrors());
        assertEquals(2, signature.getFailedConstraints().size());

        AppliedRejection rejection = signature.getAppliedRejections().get(0);
        assertEquals("MDSS-TR-NES-CERTIFICATE-POLICY", rejection.getCode());
        assertEquals("TOTAL_PASSED", rejection.getOriginalIndication(),
                "DSS'in asıl kararı rejection kanıtında korunur");
        assertEquals(RejectionCode.MDSS_TR_NES_CERTIFICATE_POLICY.getDocsUrl(), rejection.getDocsUrl());
    }

    @Test
    void dssRejectedSignature_keepsTheDssVerdict_butGetsTheClearerRootCause() {
        SignatureInfo signature = signature(false, "INDETERMINATE", "NO_CERTIFICATE_CHAIN_FOUND");
        signature.setValidationErrors(new ArrayList<>(Collections.singletonList(
                "İmza geçersiz: INDETERMINATE (NO_CERTIFICATE_CHAIN_FOUND)")));
        signature.setRootCause(new FailedConstraint("BBB_XCV_CCCBB", "güven kökü yok", FailureCategory.ROOT_CAUSE));

        AdvancedSignatureVerificationService.applyTrFindings(signature, Collections.singletonList(
                finding(RejectionCode.MDSS_TR_CERT_SIGNATURE_INVALID, "sertifika imzası bozuk")));

        assertEquals("INDETERMINATE", signature.getIndication());
        assertEquals("NO_CERTIFICATE_CHAIN_FOUND", signature.getSubIndication());
        assertEquals("MDSS-TR-CERT-SIGNATURE-INVALID", signature.getRootCause().getKey());
        assertEquals("[MDSS-TR-CERT-SIGNATURE-INVALID] sertifika imzası bozuk",
                signature.getValidationErrors().get(0));
        assertEquals("İmza geçersiz: INDETERMINATE (NO_CERTIFICATE_CHAIN_FOUND)",
                signature.getValidationErrors().get(1));
    }

    @Test
    void ruleRejection_becomesRootCause_evenWhenDssPassed() {
        // MDSS-TR-KEYUSAGE-PROFILE (ESXL1_MM_7): DSS PASSED → BBB satırı yok,
        // rootCause aksi halde boş kalırdı.
        SignatureInfo signature = signature(false, "INDETERMINATE", "CHAIN_CONSTRAINTS_FAILURE");

        AdvancedSignatureVerificationService.promoteToRootCause(signature, Collections.singletonList(
                rootCause(RejectionCode.MDSS_TR_KEYUSAGE_PROFILE, "nonRepudiation eksik")));

        assertEquals("MDSS-TR-KEYUSAGE-PROFILE", signature.getRootCause().getKey());
        assertEquals("nonRepudiation eksik", signature.getRootCause().getMessage());
        assertNull(signature.getFailedConstraints(),
                "Opt-in istenmediyse failedConstraints alanı yazılmaz");
    }

    @Test
    void ruleRejection_precedesDssLine_inOptInFailedConstraints() {
        SignatureInfo signature = signature(false, "INDETERMINATE", "CHAIN_CONSTRAINTS_FAILURE");
        FailedConstraint dss = new FailedConstraint("BBB_XCV_ISCGKU", "KeyUsage", FailureCategory.ROOT_CAUSE);
        signature.setRootCause(dss);
        signature.setFailedConstraints(new ArrayList<>(Collections.singletonList(dss)));
        FailedConstraint rule = rootCause(RejectionCode.MDSS_TR_KEYUSAGE_PROFILE, "nonRepudiation eksik");

        AdvancedSignatureVerificationService.promoteToRootCause(signature, Collections.singletonList(rule));

        assertEquals(rule, signature.getRootCause());
        assertEquals(Arrays.asList(rule, dss), signature.getFailedConstraints());
    }

    @Test
    void trFindings_keepEarlierKeyUsageRejection_andTakeOverRootCause() {
        SignatureInfo signature = signature(false, "INDETERMINATE", "CHAIN_CONSTRAINTS_FAILURE");
        AppliedRejection keyUsage = new AppliedRejection("MDSS-TR-KEYUSAGE-PROFILE", "t", "nonRepudiation eksik",
                "ERROR", "TOTAL_PASSED", null, Collections.<String, Object>emptyMap(), null);
        signature.setAppliedRejections(new ArrayList<>(Collections.singletonList(keyUsage)));
        AdvancedSignatureVerificationService.promoteToRootCause(signature, Collections.singletonList(
                rootCause(RejectionCode.MDSS_TR_KEYUSAGE_PROFILE, "nonRepudiation eksik")));

        AdvancedSignatureVerificationService.applyTrFindings(signature, Collections.singletonList(
                finding(RejectionCode.MDSS_TR_NES_QC_ETSI, "ETSI OID'si yok")));

        assertEquals("MDSS-TR-NES-QC-ETSI", signature.getRootCause().getKey());
        assertEquals(Arrays.asList("MDSS-TR-KEYUSAGE-PROFILE", "MDSS-TR-NES-QC-ETSI"), Arrays.asList(
                signature.getAppliedRejections().get(0).getCode(),
                signature.getAppliedRejections().get(1).getCode()));
    }

    private static FailedConstraint rootCause(RejectionCode code, String message) {
        return new FailedConstraint(code.getCode(), message, FailureCategory.ROOT_CAUSE);
    }

    private static SignatureInfo signature(boolean valid, String indication, String subIndication) {
        SignatureInfo signature = new SignatureInfo();
        signature.setSignatureId("S-1");
        signature.setValid(valid);
        signature.setIndication(indication);
        signature.setSubIndication(subIndication);
        signature.setValidationErrors(new ArrayList<String>());
        return signature;
    }

    private static TrComplianceFinding finding(RejectionCode code, String reason) {
        return new TrComplianceFinding(code, reason, Indication.INDETERMINATE,
                SubIndication.CHAIN_CONSTRAINTS_FAILURE, Collections.<String, Object>emptyMap());
    }
}
