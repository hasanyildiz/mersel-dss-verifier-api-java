package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import io.mersel.dss.verify.api.models.enums.SignerCertificateProfile;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link SignerCertificateProfileDetector} birim testleri.
 *
 * <p>Sınıflandırma sinyalleri TÜBİTAK e-Fatura ön hazırlık örnek paketindeki
 * gerçek sertifikalardan türetilmiştir:</p>
 *
 * <ul>
 *   <li>e-imza/NES (QC A*): politika OID {@code 2.16.792.1.2.1.1.5.7.1.1},
 *       QC statements (ETSI + KamuSM 5070), KU = digitalSignature +
 *       nonRepudiation.</li>
 *   <li>mali mühür (MM A*): politika OID {@code 2.16.792.1.2.1.1.5.7.4.1},
 *       EKU {@code 2.16.792.1.2.1.1.5.7.50.1} (her sertifikada yok — MM_38),
 *       KU = yalnız digitalSignature.</li>
 * </ul>
 */
class SignerCertificateProfileDetectorTest {

    /** CertificateWrapper final değildir; test için kanıt yöntemleri geçersiz kılınır. */
    private static CertificateWrapper certificate(
            List<String> policyIds,
            List<String> ekuOids,
            List<String> qcStatements) {
        return new CertificateWrapper(new XmlCertificate()) {
            @Override
            public List<String> getPolicyIds() {
                return policyIds != null ? policyIds : Collections.emptyList();
            }

            @Override
            public List<XmlOID> getExtendedKeyUsages() {
                if (ekuOids == null) return Collections.emptyList();
                return ekuOids.stream().map(oid -> {
                    XmlOID xmlOid = new XmlOID();
                    xmlOid.setValue(oid);
                    return xmlOid;
                }).collect(java.util.stream.Collectors.toList());
            }

            @Override
            public List<String> getOtherQcStatements() {
                return qcStatements != null ? qcStatements : Collections.emptyList();
            }
        };
    }

    // ------------------------------------------------------------------
    // Profil tespiti — politika OID'leri asıl ayrıştırıcı
    // ------------------------------------------------------------------

    @Test
    void nesPolicyOid_classifiesAsEImza() {
        assertEquals(SignerCertificateProfile.NES_E_IMZA,
                SignerCertificateProfileDetector.detect(certificate(
                        Arrays.asList("2.16.792.1.2.1.1.5.7.1.1"),
                        null, null)));
    }

    @Test
    void maliMuhurPolicyOid_classifiesAsMaliMuhur() {
        assertEquals(SignerCertificateProfile.MALI_MUHUR,
                SignerCertificateProfileDetector.detect(certificate(
                        Arrays.asList("2.16.792.1.2.1.1.5.7.4.1"),
                        null, null)));
    }

    @Test
    void maliMuhurPolicyOid_winsOverOtherSignals() {
        // Politika OID'i asıl kanıt: NES politikası yok ama NES QC statement
        // varken MM politika OID'i bulunuyorsa sonuç mali mühürdür.
        assertEquals(SignerCertificateProfile.MALI_MUHUR,
                SignerCertificateProfileDetector.detect(certificate(
                        Arrays.asList("2.16.792.1.2.1.1.5.7.4.1", "1.2.3"),
                        null,
                        Arrays.asList("2.16.792.1.61.0.1.5070.1.1"))));
    }

    @Test
    void maliMuhurEku_winsOverNesPolicyOid_likeMm39() {
        // ESXL1_MM_39 / EST_39 (MM A1 3, "CP OID Absent"): mühür EKU'su var ama
        // mühür politikası yerine NES politikası taşıyor. NES sayılsaydı
        // nonRepudiation eksikliğiyle yanlış gerekçeyle reddedilirdi; doğru
        // ret TR uyum kontrolündeki mühür politika kuralıdır.
        assertEquals(SignerCertificateProfile.MALI_MUHUR,
                SignerCertificateProfileDetector.detect(certificate(
                        Arrays.asList("2.16.792.1.2.1.1.5.7.1.1"),
                        Arrays.asList("2.16.792.1.2.1.1.5.7.50.1"),
                        null)));
    }

    // ------------------------------------------------------------------
    // Destekleyici kanıtlar — politika OID'i tanınmadığında
    // ------------------------------------------------------------------

    @Test
    void maliMuhurEkuOid_alone_classifiesAsMaliMuhur() {
        assertEquals(SignerCertificateProfile.MALI_MUHUR,
                SignerCertificateProfileDetector.detect(certificate(
                        Arrays.asList("1.2.3.4"),
                        Arrays.asList("2.16.792.1.2.1.1.5.7.50.1"),
                        null)));
    }

    @Test
    void kamuSmQcStatement_alone_classifiesAsEImza() {
        assertEquals(SignerCertificateProfile.NES_E_IMZA,
                SignerCertificateProfileDetector.detect(certificate(
                        Arrays.asList("1.2.3.4"),
                        null,
                        Arrays.asList("2.16.792.1.61.0.1.5070.1.1"))));
    }

    @Test
    void noKnownEvidence_classifiesAsUnknown() {
        assertEquals(SignerCertificateProfile.UNKNOWN,
                SignerCertificateProfileDetector.detect(certificate(
                        Arrays.asList("1.2.3.4.5"),
                        Arrays.asList("1.3.6.1.5.5.7.3.2"),
                        Arrays.asList("0.4.0.1862.1.6.2"))));
        assertEquals(SignerCertificateProfile.UNKNOWN,
                SignerCertificateProfileDetector.detect(null));
    }

    // ------------------------------------------------------------------
    // Profile göre zorunlu KeyUsage
    // ------------------------------------------------------------------

    @Test
    void eImza_requiresBothDigitalSignatureAndNonRepudiation() {
        assertEquals(
                Arrays.asList(KeyUsageBit.DIGITAL_SIGNATURE, KeyUsageBit.NON_REPUDIATION),
                SignerCertificateProfileDetector.requiredKeyUsageBits(
                        SignerCertificateProfile.NES_E_IMZA));
    }

    @Test
    void maliMuhur_requiresOnlyDigitalSignature() {
        assertEquals(
                Collections.singletonList(KeyUsageBit.DIGITAL_SIGNATURE),
                SignerCertificateProfileDetector.requiredKeyUsageBits(
                        SignerCertificateProfile.MALI_MUHUR));
    }

    @Test
    void unknownProfile_hasNoRequirement() {
        assertTrue(SignerCertificateProfileDetector.requiredKeyUsageBits(
                SignerCertificateProfile.UNKNOWN).isEmpty());
    }

    @Test
    void missingBits_eImzaWithOnlyDigitalSignature_reportsNonRepudiation() {
        // ESXL1_MM_7 (QC A1 3) vakası: yalnız digitalSignature → nonRepudiation eksik.
        assertEquals(
                Collections.singletonList(KeyUsageBit.NON_REPUDIATION),
                SignerCertificateProfileDetector.missingKeyUsageBits(
                        SignerCertificateProfile.NES_E_IMZA,
                        Collections.singletonList(KeyUsageBit.DIGITAL_SIGNATURE)));
    }

    @Test
    void missingBits_maliMuhurWithoutNonRepudiation_isNotAViolation() {
        // MM A* vakası: nonRepudiation yok ama mali mühür profili için kural dışı.
        assertTrue(SignerCertificateProfileDetector.missingKeyUsageBits(
                SignerCertificateProfile.MALI_MUHUR,
                Collections.singletonList(KeyUsageBit.DIGITAL_SIGNATURE)).isEmpty());
    }

    @Test
    void missingBits_eImzaWithBothBits_isEmpty() {
        assertTrue(SignerCertificateProfileDetector.missingKeyUsageBits(
                SignerCertificateProfile.NES_E_IMZA,
                Arrays.asList(KeyUsageBit.DIGITAL_SIGNATURE, KeyUsageBit.NON_REPUDIATION))
                .isEmpty());
    }

    @Test
    void missingBits_keyUsageAbsent_reportsAllRequired() {
        // KeyUsage uzantısı hiç yoksa tüm zorunlu bit'ler eksiktir.
        assertEquals(
                Arrays.asList(KeyUsageBit.DIGITAL_SIGNATURE, KeyUsageBit.NON_REPUDIATION),
                SignerCertificateProfileDetector.missingKeyUsageBits(
                        SignerCertificateProfile.NES_E_IMZA, null));
    }

    @Test
    void missingBits_encryptionOnlyCert_reportsAllRequired() {
        // Şifreleme sertifikasının (keyEncipherment + keyAgreement) imza
        // yetkisi yok: tüm zorunlu bit'ler eksik.
        assertEquals(
                Collections.singletonList(KeyUsageBit.DIGITAL_SIGNATURE),
                SignerCertificateProfileDetector.missingKeyUsageBits(
                        SignerCertificateProfile.MALI_MUHUR,
                        Arrays.asList(KeyUsageBit.KEY_ENCIPHERMENT, KeyUsageBit.KEY_AGREEMENT)));
    }
}
