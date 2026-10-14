package io.mersel.dss.verify.api.services.util;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import io.mersel.dss.verify.api.models.SignatureInfo;
import io.mersel.dss.verify.api.models.SignedReferenceInfo;
import io.mersel.dss.verify.api.models.TimestampInfo;
import io.mersel.dss.verify.api.models.VerificationRecommendation;
import io.mersel.dss.verify.api.models.enums.ChainRevocationStatus;
import io.mersel.dss.verify.api.services.compliance.TrComplianceFinding;
import io.mersel.dss.verify.api.services.compliance.ValidationDataChecker;
import io.mersel.dss.verify.api.models.enums.RejectionCode;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

/** Copies DSS report evidence without inferring relationships from XML nesting or changing validation decisions. */
public final class SignatureEvidenceExtractor {
    private SignatureEvidenceExtractor() { }

    public static void enrich(SignatureInfo info, SignatureWrapper wrapper) {
        info.setCounterSignature(wrapper.isCounterSignature());
        SignatureWrapper parent = wrapper.getParent();
        if (parent != null) info.setParentSignatureId(parent.getId());
        CertificateWrapper signingCertificate = wrapper.getSigningCertificate();
        if (signingCertificate != null) {
            info.setSignerCertificateProfile(SignerCertificateProfileDetector.detect(signingCertificate));
        }
        List<SignedReferenceInfo> references = new ArrayList<>();
        List<XmlDigestMatcher> matchers = wrapper.getDigestMatchers();
        if (matchers != null) {
            for (XmlDigestMatcher matcher : matchers) {
                if (matcher == null) continue;
                SignedReferenceInfo reference = new SignedReferenceInfo();
                reference.setId(matcher.getId());
                reference.setUri(matcher.getUri());
                reference.setDocumentName(matcher.getDocumentName());
                if (matcher.getType() != null) reference.setType(matcher.getType().name());
                if (matcher.getDigestMethod() != null) reference.setDigestAlgorithm(matcher.getDigestMethod().getName());
                if (matcher.getDigestValue() != null) {
                    reference.setDigestValue(Base64.getEncoder().encodeToString(matcher.getDigestValue()));
                }
                reference.setDataFound(matcher.isDataFound());
                reference.setDataIntact(matcher.isDataIntact());
                reference.setDuplicated(matcher.isDuplicated());
                references.add(reference);
            }
        }
        info.setSignedReferences(references);
        info.setRecommendations(recommendations(info, wrapper));
    }

    /** Builds the inverse relationship only from the parent IDs reported by DSS. */
    public static void connectCounterSignatures(List<SignatureInfo> signatures) {
        Map<String, SignatureInfo> byId = new LinkedHashMap<>();
        for (SignatureInfo signature : signatures) {
            signature.setCounterSignatureIds(new ArrayList<>());
            byId.put(signature.getSignatureId(), signature);
        }
        for (SignatureInfo signature : signatures) {
            SignatureInfo parent = byId.get(signature.getParentSignatureId());
            if (parent != null && Boolean.TRUE.equals(signature.getCounterSignature())
                    && parent != signature && !parent.getCounterSignatureIds().contains(signature.getSignatureId())) {
                parent.getCounterSignatureIds().add(signature.getSignatureId());
            }
        }
    }

    /** BTK Tebliği (RG 24.03.2020) özetleme algoritmaları: SHA2-256/384/512, SHA3-256/384/512. */
    static final Set<DigestAlgorithm> ALLOWED_DIGEST_ALGORITHMS = Collections.unmodifiableSet(EnumSet.of(
            DigestAlgorithm.SHA256, DigestAlgorithm.SHA384, DigestAlgorithm.SHA512,
            DigestAlgorithm.SHA3_256, DigestAlgorithm.SHA3_384, DigestAlgorithm.SHA3_512));

    static final String ARCHIVE_REQUIRED_DIGEST_POLICY = "ARCHIVE_REQUIRED_DIGEST_POLICY";
    static final String ARCHIVE_REQUIRED_REVOCATION_EVIDENCE = "ARCHIVE_REQUIRED_REVOCATION_EVIDENCE";
    static final String VALIDATION_EVIDENCE_INCOMPLETE = "VALIDATION_EVIDENCE_INCOMPLETE";

    /** Eksik doğrulama verisini bildiren ret kodları: "eksik bilginin tamamlanması" önerisi eşlik eder. */
    private static final Set<RejectionCode> MISSING_EVIDENCE_CODES = Collections.unmodifiableSet(EnumSet.of(
            RejectionCode.MDSS_TR_CERT_REF_MISSING, RejectionCode.MDSS_TR_CERT_VALUE_MISSING,
            RejectionCode.MDSS_TR_REVOCATION_REF_MISSING, RejectionCode.MDSS_TR_REVOCATION_DATA_MISSING));

    /** Maps explicit DSS policy warning keys to the legacy preservation guidance. */
    public static void enrichPolicyRecommendations(SignatureInfo info, DetailedReport report) {
        enrichPolicyRecommendations(info, report, null);
    }

    /**
     * Arşiv önerileri (rehber §2.1) yalnız geçerli ve arşivlenmemiş (arşiv zaman damgası
     * olmayan) imzada verilir:
     * <ul>
     *   <li>{@code ARCHIVE_REQUIRED_DIGEST_POLICY} — imza BTK listesi dışında bir özet
     *       algoritması kullanıyor (ör. SHA-1) veya DSS politikası özet uyarısı verdi.</li>
     *   <li>{@code ARCHIVE_REQUIRED_REVOCATION_EVIDENCE} — doğrulamada kullanılan, imzacı
     *       dışındaki bir sertifika (alt kök, OCSP, zaman damgası) kontrol zamanından sonra
     *       iptal edilmiş. İmzacı sertifikasının sonradan iptali arşiv gerekçesi değildir.</li>
     * </ul>
     * DSS'in iptal verisi tazelik uyarıları (ör. politika WARN) arşiv gerekçesi değildir.
     */
    public static void enrichPolicyRecommendations(SignatureInfo info, DetailedReport report,
                                                   SignatureWrapper wrapper) {
        if (report == null || info.getSignatureId() == null) return;
        List<VerificationRecommendation> recommendations = info.getRecommendations();
        if (recommendations == null) {
            recommendations = new ArrayList<>();
            info.setRecommendations(recommendations);
        }
        List<Message> warnings = new ArrayList<>();
        addMessages(warnings, report.getAdESValidationWarnings(info.getSignatureId()));
        if (info.getTimestamps() != null) {
            for (TimestampInfo timestamp : info.getTimestamps()) {
                if (timestamp.getTimestampId() != null) {
                    addMessages(warnings, report.getAdESValidationWarnings(timestamp.getTimestampId()));
                    addMessages(warnings, report.getAdESValidationErrors(timestamp.getTimestampId()));
                }
            }
        }
        boolean archived = wrapper != null && wrapper.getArchiveTimestamps() != null
                && !wrapper.getArchiveTimestamps().isEmpty();
        if (info.isValid() && !archived) {
            List<String> weakDigests = disallowedDigestAlgorithms(wrapper);
            if (!weakDigests.isEmpty() || hasKey(warnings, "ASCCM_DAA_ANS", "ASCCM_DAA_ANS_2")) {
                recommendations.add(recommendation(ARCHIVE_REQUIRED_DIGEST_POLICY,
                        "Geçersiz Özet Algoritması, İmza En Kısa Sürede Arşivlenmelidir",
                        (weakDigests.isEmpty()
                                ? "DSS, etkin politikanın özet algoritması kısıtını uyarı olarak bildirdi."
                                : "İmza, BTK'nın izin verdiği özet algoritmaları (SHA-256/384/512, SHA3-256/384/512) "
                                        + "dışında " + String.join(", ", weakDigests) + " kullanıyor.")
                                + " İmza geçerlidir; özet algoritması uyarısı sonucu değiştirmez. İmza en kısa "
                                + "sürede arşivlenmelidir.", "WARNING"));
            }
            List<ValidationDataChecker.LaterRevocation> later = wrapper != null
                    ? ValidationDataChecker.laterRevocations(wrapper, signerControlTime(wrapper))
                    : Collections.<ValidationDataChecker.LaterRevocation>emptyList();
            if (!later.isEmpty()) {
                List<String> items = new ArrayList<>();
                for (ValidationDataChecker.LaterRevocation revocation : later) {
                    items.add(revocation.getRole() + " '" + revocation.getSubject() + "' ("
                            + display(revocation.getRevocationDate()) + ")");
                }
                recommendations.add(recommendation(ARCHIVE_REQUIRED_REVOCATION_EVIDENCE, "Dosya arşivlenmelidir",
                        "Doğrulamada kullanılan sertifika, imza zamanından sonra iptal edilmiş: "
                                + String.join("; ", items) + ". İmza geçerlidir; ancak bu kanıt zamanla "
                                + "doğrulanamaz hale gelir. İmza arşivlenmelidir (arşiv zaman damgası).",
                        "WARNING"));
            }
        }
        if (!info.isValid() && !hasRecommendation(info, VALIDATION_EVIDENCE_INCOMPLETE)) {
            List<Message> errors = report.getAdESValidationErrors(info.getSignatureId());
            if (hasKey(errors, "BBB_XCV_IRDPFC_ANS", "BBB_XCV_IARDPFC_ANS", "BBB_XCV_IRDPFRC_ANS")
                    || "NO_SIGNING_CERTIFICATE_FOUND".equals(info.getSubIndication())
                    || "NO_CERTIFICATE_CHAIN_FOUND".equals(info.getSubIndication())
                    || "SIGNED_DATA_NOT_FOUND".equals(info.getSubIndication())) {
                recommendations.add(missingEvidenceRecommendation(
                        "DSS gerekli sertifika, iptal kanıtı veya imzalı içeriğe ulaşamadı."));
            }
        }
    }

    /**
     * TR uyum kuralı imzayı reddettiğinde önerileri karara uydurur: geçersiz imza için arşiv
     * önerileri kaldırılır (arşivleme geçersiz imzayı düzeltmez); eksik referans veya iptal
     * verisi bulgusuna "Eksik bilginin tamamlanması gerekmektedir" önerisi eşlik eder.
     */
    public static void applyRejectionRecommendations(SignatureInfo info, List<TrComplianceFinding> findings) {
        List<VerificationRecommendation> recommendations = info.getRecommendations() != null
                ? new ArrayList<>(info.getRecommendations()) : new ArrayList<VerificationRecommendation>();
        if (!info.isValid()) {
            recommendations.removeIf(r -> ARCHIVE_REQUIRED_DIGEST_POLICY.equals(r.getCode())
                    || ARCHIVE_REQUIRED_REVOCATION_EVIDENCE.equals(r.getCode()));
        }
        List<String> missing = new ArrayList<>();
        for (TrComplianceFinding finding : findings) {
            if (MISSING_EVIDENCE_CODES.contains(finding.getCode())) {
                missing.add(finding.getReason().replace(" Eksik bilginin tamamlanması gerekmektedir.", ""));
            }
        }
        if (!missing.isEmpty()) {
            recommendations.removeIf(r -> VALIDATION_EVIDENCE_INCOMPLETE.equals(r.getCode()));
            recommendations.add(0, missingEvidenceRecommendation(String.join(" ", missing)));
        }
        info.setRecommendations(recommendations);
    }

    private static VerificationRecommendation missingEvidenceRecommendation(String detail) {
        return recommendation(VALIDATION_EVIDENCE_INCOMPLETE, "Eksik bilginin tamamlanması gerekmektedir",
                detail + " Eksik veriyi tamamlayıp yeniden doğrulayın; bu öneri sonucu geçerli yapmaz.", "WARNING");
    }

    /** İmzanın ve imzalı referanslarının BTK listesi dışındaki özet algoritmaları (ör. SHA1). */
    static List<String> disallowedDigestAlgorithms(SignatureWrapper wrapper) {
        Set<String> names = new LinkedHashSet<>();
        if (wrapper == null) return new ArrayList<>(names);
        if (wrapper.getDigestAlgorithm() != null && !ALLOWED_DIGEST_ALGORITHMS.contains(wrapper.getDigestAlgorithm())) {
            names.add(wrapper.getDigestAlgorithm().getName());
        }
        if (wrapper.getDigestMatchers() != null) {
            for (XmlDigestMatcher matcher : wrapper.getDigestMatchers()) {
                if (matcher != null && matcher.getDigestMethod() != null
                        && !ALLOWED_DIGEST_ALGORITHMS.contains(matcher.getDigestMethod())) {
                    names.add(matcher.getDigestMethod().getName());
                }
            }
        }
        return new ArrayList<>(names);
    }

    /** İmzacı zincirinin kontrol zamanı: en erken sağlam imza zaman damgası, yoksa doğrulama zamanı. */
    private static Date signerControlTime(SignatureWrapper wrapper) {
        Date earliest = null;
        if (wrapper.getTimestampList() != null) {
            for (TimestampWrapper timestamp : wrapper.getTimestampList()) {
                if (timestamp.getType() == TimestampType.SIGNATURE_TIMESTAMP && timestamp.isSignatureIntact()
                        && timestamp.isMessageImprintDataIntact() && timestamp.getProductionTime() != null
                        && (earliest == null || timestamp.getProductionTime().before(earliest))) {
                    earliest = timestamp.getProductionTime();
                }
            }
        }
        return earliest != null ? earliest : new Date();
    }

    private static String display(Date date) {
        if (date == null) return "tarih bilinmiyor";
        SimpleDateFormat format = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss", new Locale("tr", "TR"));
        format.setTimeZone(TimeZone.getTimeZone("Europe/Istanbul"));
        return format.format(date);
    }

    private static boolean hasRecommendation(SignatureInfo info, String code) {
        if (info.getRecommendations() == null) return false;
        for (VerificationRecommendation recommendation : info.getRecommendations()) {
            if (code.equals(recommendation.getCode())) return true;
        }
        return false;
    }

    private static void addMessages(List<Message> target, List<Message> messages) {
        if (messages != null) target.addAll(messages);
    }

    private static boolean hasKey(List<Message> messages, String... keys) {
        if (messages == null) return false;
        for (Message message : messages) {
            if (message == null) continue;
            for (String key : keys) if (key.equals(message.getKey())) return true;
        }
        return false;
    }

    private static List<VerificationRecommendation> recommendations(SignatureInfo info, SignatureWrapper wrapper) {
        List<VerificationRecommendation> result = new ArrayList<>();
        if (!wrapper.isTrustedChain()) {
            result.add(recommendation("TRUST_CHAIN_INCOMPLETE", "Güven zincirini inceleyin",
                    "DSS, güvenilir köke ulaşan bir sertifika zinciri bildirmedi. Ara sertifikaları ve etkin güven deposunu kontrol edin.", "WARNING"));
        }
        if (info.getChainRevocationStatus() == ChainRevocationStatus.NOT_CHECKED
                || info.getChainRevocationStatus() == ChainRevocationStatus.UNKNOWN) {
            result.add(recommendation("REVOCATION_EVIDENCE_MISSING", "İptal kanıtlarını tamamlayın",
                    "Zincirin iptal durumu kesinleştirilemedi. İlgili OCSP/SİL kanıtlarını ve çevrimiçi erişimi inceleyin.", "WARNING"));
        }
        if (info.getTimestamps() != null) {
            for (TimestampInfo timestamp : info.getTimestamps()) {
                if (!timestamp.isValid() || timestamp.getIndication() == null) {
                    result.add(recommendation("TIMESTAMP_VALIDATION_INCOMPLETE", "Zaman damgası kanıtını inceleyin",
                            "En az bir zaman damgasının tam doğrulama sonucu başarılı değil veya mevcut değil. Damga özeti, TSA zinciri ve DSS sonucunu inceleyin.", "WARNING"));
                    break;
                }
            }
        }
        for (SignedReferenceInfo reference : info.getSignedReferences()) {
            if (!reference.isDataFound() || !reference.isDataIntact() || reference.isDuplicated()) {
                result.add(recommendation("SIGNED_REFERENCE_INCOMPLETE", "İmzalı içerik eşleşmesini inceleyin",
                        "DSS en az bir imza referansını eksik, değiştirilmiş veya yinelenmiş olarak bildirdi. Ayrık imzanın özgün belgesini ve referans ayrıntılarını kontrol edin.", "WARNING"));
                break;
            }
        }
        return result;
    }

    private static VerificationRecommendation recommendation(String code, String title, String description, String severity) {
        VerificationRecommendation value = new VerificationRecommendation();
        value.setCode(code);
        value.setTitle(title);
        value.setDescription(description);
        value.setSeverity(severity);
        return value;
    }
}
