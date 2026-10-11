package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import io.mersel.dss.verify.api.models.enums.SignerCertificateProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * İmzacı sertifikasını OID kanıtlarından {@link SignerCertificateProfile}
 * olarak sınıflandırır ve profile göre zorunlu {@link KeyUsageBit} setini
 * verir.
 *
 * <p>Kayınak veri: TÜBİTAK e-Fatura ön hazırlık örnek paketindeki gerçek
 * sertifikalar.</p>
 *
 * <table border="1">
 *   <caption>Profil sinyalleri</caption>
 *   <tr><th></th><th>NES / e-imza (QC A*)</th><th>Mali mühür (MM A*)</th></tr>
 *   <tr><td>certificatePolicies</td><td>{@code 2.16.792.1.2.1.1.5.7.1.1}</td>
 *       <td>{@code 2.16.792.1.2.1.1.5.7.4.1}</td></tr>
 *   <tr><td>extendedKeyUsage</td><td>—</td>
 *       <td>{@code 2.16.792.1.2.1.1.5.7.50.1} (her MM sertifikasında yok)</td></tr>
 *   <tr><td>QCStatements</td>
 *       <td>ETSI {@code 0.4.0.1862.1.1} + KamuSM {@code 2.16.792.1.61.0.1.5070.x}</td>
 *       <td>yok</td></tr>
 *   <tr><td>KeyUsage (fiili)</td><td>digitalSignature + nonRepudiation</td>
 *       <td>yalnız digitalSignature</td></tr>
 * </table>
 *
 * <p>Profile göre KeyUsage zorunluluğu (TÜBİTAK paralel):</p>
 * <ul>
 *   <li>{@code NES_E_IMZA} — {@code digitalSignature} <strong>ve</strong>
 *       {@code nonRepudiation} birlikte zorunlu (ETSI EN 319 411-1
 *       contentCommitment; örnek negatif vaka: yalnız digitalSignature
 *       taşıyan sertifikalar reddedilmelidir).</li>
 *   <li>{@code MALI_MUHUR} — yalnız {@code digitalSignature} zorunlu;
 *       mühür sertifikalarında nonRepudiation bulunmaz, aranmaz.</li>
 *   <li>{@code UNKNOWN} — profile özgü zorunluluk uygulanmaz; etkin politikanın
 *       kendi KeyUsage kuralı geçerli kalır.</li>
 * </ul>
 */
public final class SignerCertificateProfileDetector {

    private static final Logger logger =
            LoggerFactory.getLogger(SignerCertificateProfileDetector.class);

    /** KamuSM nitelikli e-imza sertifikası politika OID'i (QC A* ailesi). */
    public static final String NES_POLICY_OID = "2.16.792.1.2.1.1.5.7.1.1";

    /** KamuSM mali mühür sertifikası politika OID'i (MM A* ailesi). */
    public static final String MALI_MUHUR_POLICY_OID = "2.16.792.1.2.1.1.5.7.4.1";

    /** Mali mühür EKU OID'i (MM_38'de görüldüğü üzere her sertifikada bulunmaz). */
    public static final String MALI_MUHUR_EKU_OID = "2.16.792.1.2.1.1.5.7.50.1";

    /** KamuSM "5070 sayılı kanuna göre nitelikli" QC statement OID öneki. */
    public static final String KAMUSM_QC_STATEMENT_OID_PREFIX = "2.16.792.1.61.0.1.5070.";

    private SignerCertificateProfileDetector() {
    }

    /**
     * Sertifikayı OID kanıtlarından profiline sınıflandırır.
     *
     * <p>Sıra: mali mühür kanıtı (politika OID'i <strong>veya</strong> EKU)
     * önce gelir, NES politika OID'i sonra; KamuSM QC statement yalnızca
     * hiçbir politika/EKU kanıtı yokken destekleyicidir. Mali mühür EKU'su
     * NES politika OID'inin önündedir: NES politikasını yanlışlıkla taşıyan
     * bir mühür sertifikası (ESXL1_MM_39 / EST_39, "CP OID Absent") NES
     * sayılmamalıdır — o vaka TR uyum kontrolündeki mali mühür politika
     * kuralıyla ({@code MDSS-TR-SEAL-CERTIFICATE-POLICY}) reddedilir.
     * {@code TrComplianceChecker} da mühürü aynı kuralla ayırır. Kanıt yoksa
     * {@link SignerCertificateProfile#UNKNOWN} döner — tahmin yapılmaz.</p>
     */
    public static SignerCertificateProfile detect(CertificateWrapper certificate) {
        if (certificate == null) {
            return SignerCertificateProfile.UNKNOWN;
        }
        List<String> policyIds = safePolicyIds(certificate);
        if (policyIds.contains(MALI_MUHUR_POLICY_OID)
                || hasExtendedKeyUsage(certificate, MALI_MUHUR_EKU_OID)) {
            return SignerCertificateProfile.MALI_MUHUR;
        }
        if (policyIds.contains(NES_POLICY_OID)) {
            return SignerCertificateProfile.NES_E_IMZA;
        }
        if (hasKamusmQcStatement(certificate)) {
            return SignerCertificateProfile.NES_E_IMZA;
        }
        return SignerCertificateProfile.UNKNOWN;
    }

    /** Profile göre birlikte zorunlu KeyUsage bit'leri (bilinmeyen profil → boş). */
    public static List<KeyUsageBit> requiredKeyUsageBits(SignerCertificateProfile profile) {
        switch (profile) {
            case NES_E_IMZA:
                return Arrays.asList(KeyUsageBit.DIGITAL_SIGNATURE, KeyUsageBit.NON_REPUDIATION);
            case MALI_MUHUR:
                return Collections.singletonList(KeyUsageBit.DIGITAL_SIGNATURE);
            default:
                return Collections.emptyList();
        }
    }

    /**
     * Zorunlu bit'lerden sertifikada bulunmayanlar. Boş liste → ihlal yok
     * (veya profil bilinmiyor). KeyUsage uzantısı hiç olmayan sertifikalarda
     * tüm zorunlu bit'ler eksik döner; RFC 5280'ın "uzantı yoksa her kullanım
     * serbest" yorumu TÜBİTAK doğrulayıcısında kabul görmez.
     */
    public static List<KeyUsageBit> missingKeyUsageBits(
            SignerCertificateProfile profile, List<KeyUsageBit> present) {
        List<KeyUsageBit> required = requiredKeyUsageBits(profile);
        if (required.isEmpty()) {
            return Collections.emptyList();
        }
        if (present == null || present.isEmpty()) {
            return required;
        }
        List<KeyUsageBit> missing = new java.util.ArrayList<>();
        for (KeyUsageBit bit : required) {
            if (!present.contains(bit)) {
                missing.add(bit);
            }
        }
        return missing;
    }

    private static List<String> safePolicyIds(CertificateWrapper certificate) {
        try {
            List<String> ids = certificate.getPolicyIds();
            return ids != null ? ids : Collections.emptyList();
        } catch (Exception e) {
            logger.debug("Sertifika politika OID'leri okunamadı: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    private static boolean hasExtendedKeyUsage(CertificateWrapper certificate, String oid) {
        try {
            List<XmlOID> ekus = certificate.getExtendedKeyUsages();
            if (ekus == null) {
                return false;
            }
            for (XmlOID eku : ekus) {
                if (eku != null && oid.equals(eku.getValue())) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            logger.debug("Sertifika EKU OID'leri okunamadı: {}", e.getMessage());
            return false;
        }
    }

    private static boolean hasKamusmQcStatement(CertificateWrapper certificate) {
        try {
            List<String> statements = certificate.getOtherQcStatements();
            if (statements == null) {
                return false;
            }
            for (String statement : statements) {
                if (statement != null
                        && statement.startsWith(KAMUSM_QC_STATEMENT_OID_PREFIX)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            logger.debug("Sertifika QC statement OID'leri okunamadı: {}", e.getMessage());
            return false;
        }
    }
}
