package io.mersel.dss.verify.api.services.compliance;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import io.mersel.dss.verify.api.models.enums.RejectionCode;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;
import java.util.function.Function;

/**
 * TÜBİTAK e-Fatura ön hazırlık değerlendirmesindeki MA3 doğrulama politikasının
 * DSS politika şemasıyla ifade edilemeyen kurallarını DSS doğrulamasından sonra uygular.
 *
 * <ul>
 *   <li><b>Ayrık imza</b> — üst seviye XAdES imza, imzalanan veriye belge dışından
 *       başvuruyorsa ve özgün belge gönderilmediyse ya da gönderilen belge ayrık
 *       referansları doğrulamıyorsa reddedilir. Özgün belgeyle doğrulanan ayrık imza,
 *       enveloping ve enveloped kabul edilir; karar DSS'indir.</li>
 *   <li><b>Bozuk sertifika imzası</b> — zincir bir sertifikada kopuyor ve aynı DN'li
 *       aday düzenleyicilerin hiçbiri o sertifikanın imzasını doğrulamıyorsa.
 *       DSS bu durumu yalnız "zincir güven kökü içermiyor" olarak raporlar.</li>
 *   <li><b>İmza zamanında sertifika geçerliliği</b> — en erken imza zaman damgası
 *       (yoksa beyan edilen imza zamanı) sertifikanın geçerlilik aralığı dışındaysa.
 *       DSS iptal verisi seçiminde durduğunda süre kontrolüne hiç ulaşmaz.</li>
 *   <li><b>SİL geçerlilik süresi</b> — MA3 {@code CRLDateChecker} eşdeğeri: zincirdeki
 *       bir sertifika için yalnız SİL varsa ve hiçbirinin nextUpdate'i kontrol zamanını
 *       (imza zaman damgası, yoksa doğrulama zamanı) kapsamıyorsa.</li>
 *   <li><b>NES / mali mühür sertifika profili</b> — MA3 {@code QualifiedCertificateChecker}
 *       (UserNotice, ETSI ve BTK QC OID'leri) ve mali mühür politikası
 *       (EKU 2.16.792.1.2.1.1.5.7.50.1, politika 2.16.792.1.2.1.1.5.7.4.1). NES
 *       nonRepudiation kuralı burada değil, bayraktan bağımsız
 *       {@code MDSS-TR-KEYUSAGE-PROFILE} kontrolündedir.</li>
 * </ul>
 *
 * <p>Kurallar saf fonksiyonlardır ({@code check*}); {@link #evaluate} DSS diagnostic
 * verisinden girdileri çıkarır. Bulgular öncelik sırasıyla döner; ilki imzanın kök
 * nedeni olur.</p>
 */
@Component
public class TrComplianceChecker {

    private static final Logger logger = LoggerFactory.getLogger(TrComplianceChecker.class);

    public static final String OID_SEAL_POLICY = "2.16.792.1.2.1.1.5.7.4.1";
    public static final String OID_SEAL_EKU = "2.16.792.1.2.1.1.5.7.50.1";
    public static final String OID_QC_ETSI_COMPLIANCE = "0.4.0.1862.1.1";
    public static final String OID_QC_BTK = "2.16.792.1.61.0.1.5070.1.1";
    static final String OID_CERTIFICATE_POLICIES = "2.5.29.32";
    static final String OID_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3";

    static final String TIME_SOURCE_SIGNATURE_TIMESTAMP = "imza zaman damgası";
    static final String TIME_SOURCE_CLAIMED = "imzacının beyan ettiği imza zamanı";
    static final String TIME_SOURCE_VALIDATION = "doğrulama zamanı";

    private static final String[] KEY_USAGE_NAMES = {
            "digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment",
            "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"};

    /** Sertifika imzası JDK'nın desteklemediği algoritmalarda da (RSA-PSS, EC) doğrulanabilsin. */
    private static final Provider BC = new BouncyCastleProvider();

    /**
     * DSS'in imzaya ait referans/zaman/zincir verisi + çağıranın sağladığı bağlam.
     *
     * @param certificatePool          bozuk sertifika imzası için aday düzenleyiciler (güven
     *                                 kökleri, belgedeki sertifikalar)
     * @param originalDocumentProvided istekte özgün belge ({@code originalDocument}) gönderildi mi;
     *                                 ayrık imza yalnız bu belgeyle doğrulanırsa kabul edilir
     * @param issuerLookup             havuzda aynı DN'li aday yoksa düzenleyiciyi getirir (ör. AIA);
     *                                 {@code null} olabilir
     */
    public List<TrComplianceFinding> evaluate(SignatureWrapper signature,
                                              Collection<CertificateToken> certificatePool,
                                              List<String> externalReferenceUris,
                                              boolean originalDocumentProvided,
                                              Date validationTime,
                                              Function<X509Certificate, Collection<X509Certificate>> issuerLookup) {
        List<TrComplianceFinding> findings = new ArrayList<>();
        if (signature == null) {
            return findings;
        }
        if (!signature.isCounterSignature()) {
            add(findings, checkDetached(externalReferenceUris, originalDocumentProvided,
                    signature.getDigestMatchers()));
        }

        Map<String, X509Certificate> poolById = indexById(certificatePool);
        List<CertificateWrapper> chain = signature.getCertificateChain();
        if (chain != null && !chain.isEmpty()) {
            CertificateWrapper last = chain.get(chain.size() - 1);
            if (!last.isTrusted() && !last.isSelfSigned()) {
                X509Certificate broken = x509(last, poolById);
                if (broken != null) {
                    List<X509Certificate> candidates = new ArrayList<>(poolById.values());
                    if (issuerLookup != null && !hasIssuerCandidate(broken, candidates)) {
                        try {
                            candidates.addAll(issuerLookup.apply(broken));
                        } catch (RuntimeException e) {
                            logger.debug("TR uyum: düzenleyici aranamadı ({}): {}",
                                    broken.getSubjectX500Principal(), e.toString());
                        }
                    }
                    add(findings, checkIssuerSignature(broken, chain.size() == 1, candidates));
                }
            }
        }

        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        if (signingCertificate == null) {
            return findings;
        }
        TimestampWrapper poe = earliestSignatureTimestamp(signature);
        Date signingTime = poe != null ? poe.getProductionTime() : signature.getClaimedSigningTime();
        String signingTimeSource = poe != null ? TIME_SOURCE_SIGNATURE_TIMESTAMP : TIME_SOURCE_CLAIMED;
        add(findings, checkValidityAtSigningTime(signingCertificate.getNotBefore(),
                signingCertificate.getNotAfter(), signingTime, signingTimeSource));

        Date controlTime = poe != null ? poe.getProductionTime() : validationTime;
        String controlSource = poe != null ? TIME_SOURCE_SIGNATURE_TIMESTAMP : TIME_SOURCE_VALIDATION;
        if (chain != null) {
            for (int i = 0; i < chain.size(); i++) {
                CertificateWrapper certificate = chain.get(i);
                if (certificate.isTrusted() || certificate.isSelfSigned()) {
                    continue;
                }
                TrComplianceFinding crl = checkCrlValidity(i == 0, subjectOf(certificate, poolById),
                        revocationEvidence(certificate), controlTime, controlSource);
                if (crl != null) {
                    findings.add(crl);
                    break;
                }
            }
        }

        X509Certificate signer = x509(signingCertificate, poolById);
        if (signer != null) {
            findings.addAll(checkCertificateProfile(signer));
        } else {
            logger.warn("TR uyum: imzacı sertifikasının baytları bulunamadı (signatureId={}); "
                    + "NES/mali mühür profil kontrolü atlandı.", signature.getId());
        }
        return findings;
    }

    // ---------------------------------------------------------------------------------
    // Kurallar
    // ---------------------------------------------------------------------------------

    /**
     * Ayrık imza yalnız özgün belgeyle doğrulanabildiğinde kabul edilir: özgün belge
     * gönderildiyse her ayrık referansın DSS özet eşleştiricisi veriyi bulmuş ve özeti
     * tutmuş olmalıdır. Bu durumda bulgu üretilmez, karar DSS'indir.
     *
     * @param digestMatchers imzanın DSS özet eşleştiricileri (URI'leri DSS'te decode edilmiş)
     */
    static TrComplianceFinding checkDetached(List<String> externalReferenceUris,
                                             boolean originalDocumentProvided,
                                             List<XmlDigestMatcher> digestMatchers) {
        if (externalReferenceUris == null || externalReferenceUris.isEmpty()) {
            return null;
        }
        String uris = String.join(", ", externalReferenceUris);
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("externalReferenceUris", new ArrayList<>(externalReferenceUris));
        evidence.put("originalDocumentProvided", originalDocumentProvided);
        if (!originalDocumentProvided) {
            return new TrComplianceFinding(RejectionCode.MDSS_TR_XADES_DETACHED,
                    "Ayrık (detached) imza, imzalanan veriye belge dışından başvuruyor (" + uris + ") "
                            + "ve özgün belge (originalDocument) gönderilmedi; imzalanan veri "
                            + "doğrulanamaz. Ayrık imza yalnız özgün belgeyle birlikte gönderilip "
                            + "belge imzayla eşleştiğinde kabul edilir.",
                    Indication.INDETERMINATE, SubIndication.SIGNED_DATA_NOT_FOUND, evidence);
        }

        List<String> notFound = new ArrayList<>();
        List<String> digestMismatch = new ArrayList<>();
        for (String uri : externalReferenceUris) {
            List<XmlDigestMatcher> matching = digestMatchersFor(uri, digestMatchers);
            boolean found = !matching.isEmpty();
            boolean intact = found;
            for (XmlDigestMatcher matcher : matching) {
                found &= matcher.isDataFound();
                intact &= matcher.isDataIntact();
            }
            if (!found) {
                notFound.add(uri);
            } else if (!intact) {
                digestMismatch.add(uri);
            }
        }
        if (notFound.isEmpty() && digestMismatch.isEmpty()) {
            return null;
        }
        evidence.put("unresolvedReferenceUris", notFound);
        evidence.put("digestMismatchReferenceUris", digestMismatch);
        if (!notFound.isEmpty()) {
            return new TrComplianceFinding(RejectionCode.MDSS_TR_XADES_DETACHED,
                    "Ayrık (detached) imzanın özgün belgesi gönderildi ancak şu referanslar bu "
                            + "belgeyle eşleştirilemedi: " + String.join(", ", notFound) + ". "
                            + "İmzalanan verinin tamamı doğrulanamadı.",
                    Indication.INDETERMINATE, SubIndication.SIGNED_DATA_NOT_FOUND, evidence);
        }
        return new TrComplianceFinding(RejectionCode.MDSS_TR_XADES_DETACHED,
                "Ayrık (detached) imzanın özgün belgesi gönderildi ancak imzalanan özetle "
                        + "eşleşmiyor (" + String.join(", ", digestMismatch) + "): gönderilen belge "
                        + "imzalanan belge değil ya da imzadan sonra değiştirilmiş.",
                Indication.TOTAL_FAILED, SubIndication.HASH_FAILURE, evidence);
    }

    /** DSS referans URI'yi decode ederek saklar; ham ve decode edilmiş biçimle eşleştirilir. */
    private static List<XmlDigestMatcher> digestMatchersFor(String uri, List<XmlDigestMatcher> digestMatchers) {
        List<XmlDigestMatcher> matching = new ArrayList<>();
        if (digestMatchers == null) {
            return matching;
        }
        String decoded = DSSUtils.decodeURI(uri);
        for (XmlDigestMatcher matcher : digestMatchers) {
            if (matcher != null && matcher.getUri() != null
                    && (matcher.getUri().equals(uri) || matcher.getUri().equals(decoded))) {
                matching.add(matcher);
            }
        }
        return matching;
    }

    /**
     * Zincirin koptuğu sertifikayı, aynı DN'li aday düzenleyicilerle doğrular. Aday yoksa
     * (düzenleyici gerçekten bulunamadı) veya doğrulama yapılamıyorsa bulgu üretmez.
     */
    static TrComplianceFinding checkIssuerSignature(X509Certificate certificate, boolean signer,
                                                    List<X509Certificate> pool) {
        List<X509Certificate> candidates = new ArrayList<>();
        for (X509Certificate candidate : pool) {
            if (candidate != null && !candidate.equals(certificate)
                    && candidate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                candidates.add(candidate);
            }
        }
        if (candidates.isEmpty()) {
            return null;
        }
        Set<String> candidateHashes = new LinkedHashSet<>();
        for (X509Certificate candidate : candidates) {
            try {
                certificate.verify(candidate.getPublicKey(), BC);
                return null;
            } catch (SignatureException | InvalidKeyException e) {
                candidateHashes.add(sha256(candidate));
            } catch (Exception e) {
                logger.debug("TR uyum: sertifika imzası doğrulanamadı ({}); bulgu üretilmedi: {}",
                        certificate.getSubjectX500Principal(), e.toString());
                return null;
            }
        }
        String issuer = certificate.getIssuerX500Principal().getName();
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("certificateSubject", certificate.getSubjectX500Principal().getName());
        evidence.put("issuerSubject", issuer);
        evidence.put("candidateIssuerSha256", new ArrayList<>(candidateHashes));
        return new TrComplianceFinding(RejectionCode.MDSS_TR_CERT_SIGNATURE_INVALID,
                (signer ? "İmzacı sertifikasının" : "Ara sertifikanın ('"
                        + certificate.getSubjectX500Principal().getName() + "')")
                        + " imzası, onu düzenleyen '" + issuer + "' sertifikasının açık anahtarıyla "
                        + "doğrulanamadı; sertifika imzası bozuk veya sahte. Bu yüzden güvenilir köke "
                        + "giden zincir kurulamıyor.",
                Indication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, evidence);
    }

    private static boolean hasIssuerCandidate(X509Certificate certificate, List<X509Certificate> pool) {
        for (X509Certificate candidate : pool) {
            if (candidate != null && !candidate.equals(certificate)
                    && candidate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                return true;
            }
        }
        return false;
    }

    static TrComplianceFinding checkValidityAtSigningTime(Date notBefore, Date notAfter,
                                                          Date signingTime, String source) {
        if (signingTime == null) {
            return null;
        }
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("notBefore", iso(notBefore));
        evidence.put("notAfter", iso(notAfter));
        evidence.put("signingTime", iso(signingTime));
        evidence.put("signingTimeSource", source);
        if (notAfter != null && signingTime.after(notAfter)) {
            return new TrComplianceFinding(RejectionCode.MDSS_TR_CERT_EXPIRED_AT_SIGNING_TIME,
                    "İmzacı sertifikasının süresi imza zamanından önce dolmuş: sertifika "
                            + display(notAfter) + " tarihinde sona ermiş, imza zamanı "
                            + display(signingTime) + " (" + source + "). Süresi dolmuş sertifikayla "
                            + "atılan imza geçerli değildir.",
                    Indication.INDETERMINATE, SubIndication.OUT_OF_BOUNDS_NO_POE, evidence);
        }
        if (notBefore != null && signingTime.before(notBefore)) {
            return new TrComplianceFinding(RejectionCode.MDSS_TR_CERT_NOT_YET_VALID_AT_SIGNING_TIME,
                    "İmzacı sertifikası imza zamanında henüz geçerli değildi: sertifika "
                            + display(notBefore) + " tarihinde başlıyor, imza zamanı "
                            + display(signingTime) + " (" + source + ").",
                    Indication.TOTAL_FAILED, SubIndication.NOT_YET_VALID, evidence);
        }
        return null;
    }

    /**
     * Sertifika için yalnız SİL varsa ve hiçbirinin geçerliliği kontrol zamanını kapsamıyorsa
     * bulgu üretir. OCSP yanıtı veya kapsayan bir SİL varsa karar DSS'indir.
     */
    static TrComplianceFinding checkCrlValidity(boolean signer, String certificateSubject,
                                                List<RevocationEvidence> revocations,
                                                Date controlTime, String controlSource) {
        if (revocations == null || revocations.isEmpty() || controlTime == null) {
            return null;
        }
        RevocationEvidence latest = null;
        for (RevocationEvidence revocation : revocations) {
            if (!revocation.isCrl()) {
                return null;
            }
            if (revocation.nextUpdate == null || !revocation.nextUpdate.before(controlTime)) {
                return null;
            }
            if (latest == null || revocation.nextUpdate.after(latest.nextUpdate)) {
                latest = revocation;
            }
        }
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("certificateSubject", certificateSubject);
        evidence.put("crlThisUpdate", iso(latest.thisUpdate));
        evidence.put("crlNextUpdate", iso(latest.nextUpdate));
        evidence.put("crlOrigin", latest.origin);
        evidence.put("controlTime", iso(controlTime));
        evidence.put("controlTimeSource", controlSource);
        return new TrComplianceFinding(RejectionCode.MDSS_TR_CRL_EXPIRED,
                (signer ? "İmzacı sertifikasının" : "'" + certificateSubject + "' ara sertifikasının")
                        + " iptal kontrolünde kullanılan SİL'in geçerlilik süresi dolmuş: SİL "
                        + display(latest.thisUpdate) + " tarihinde yayımlanmış, bir sonraki yayın "
                        + "tarihi (nextUpdate) " + display(latest.nextUpdate) + "; kontrol zamanı "
                        + display(controlTime) + " (" + controlSource + "). Süresi dolmuş SİL ile "
                        + "sertifikanın iptal durumu doğrulanamaz.",
                Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence);
    }

    /**
     * Mali mühür (EKU 50.1 veya politika 4.1 taşıyan) sertifikalarda mali mühür
     * politikasını, diğer imzacı sertifikalarında NES kurallarını uygular.
     */
    static List<TrComplianceFinding> checkCertificateProfile(X509Certificate certificate) {
        List<TrComplianceFinding> findings = new ArrayList<>();
        List<String> extendedKeyUsages = extendedKeyUsages(certificate);
        Map<String, Boolean> policies = certificatePolicies(certificate);
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("certificateSubject", certificate.getSubjectX500Principal().getName());
        evidence.put("certificatePolicies", new ArrayList<>(policies.keySet()));

        boolean seal = extendedKeyUsages.contains(OID_SEAL_EKU) || policies.containsKey(OID_SEAL_POLICY);
        if (seal) {
            evidence.put("extendedKeyUsages", extendedKeyUsages);
            if (!extendedKeyUsages.contains(OID_SEAL_EKU)) {
                findings.add(profile(RejectionCode.MDSS_TR_SEAL_EXTENDED_KEY_USAGE,
                        "Mali mühür sertifikasının genişletilmiş anahtar kullanımında (EKU) "
                                + OID_SEAL_EKU + " yok. Mevcut EKU: " + listOrNone(extendedKeyUsages) + ".",
                        evidence));
            }
            if (!policies.containsKey(OID_SEAL_POLICY)) {
                findings.add(profile(RejectionCode.MDSS_TR_SEAL_CERTIFICATE_POLICY,
                        "Mali mühür sertifikası " + OID_SEAL_POLICY + " sertifika politikasını taşımıyor. "
                                + "Mevcut politikalar: " + listOrNone(policies.keySet()) + ".",
                        evidence));
            }
            return findings;
        }

        List<String> keyUsages = keyUsages(certificate);
        List<String> qcStatements = qcStatementIds(certificate);
        evidence.put("keyUsages", keyUsages);
        evidence.put("qcStatements", qcStatements);
        // nonRepudiation burada denetlenmez: profil bazlı KeyUsage kuralı
        // (MDSS-TR-KEYUSAGE-PROFILE) bu bayraktan bağımsız uygulanır; burada da
        // üretmek aynı imzaya ikinci bir ret eklerdi.
        if (!policies.containsValue(Boolean.TRUE)) {
            findings.add(profile(RejectionCode.MDSS_TR_NES_CERTIFICATE_POLICY,
                    "Nitelikli elektronik sertifikanın sertifika politikalarında kullanıcı bildirimi "
                            + "(UserNotice, " + PolicyQualifierId.id_qt_unotice.getId() + ") yok. "
                            + "Politikalar: " + listOrNone(policies.keySet()) + ".",
                    evidence));
        }
        if (!qcStatements.contains(OID_QC_ETSI_COMPLIANCE)) {
            findings.add(profile(RejectionCode.MDSS_TR_NES_QC_ETSI,
                    "Nitelikli sertifika ibarelerinde (QCStatements) ETSI nitelikli sertifika OID'si "
                            + OID_QC_ETSI_COMPLIANCE + " yok. Mevcut ibareler: "
                            + listOrNone(qcStatements) + ".",
                    evidence));
        }
        if (!qcStatements.contains(OID_QC_BTK)) {
            findings.add(profile(RejectionCode.MDSS_TR_NES_QC_BTK,
                    "Nitelikli sertifika ibarelerinde (QCStatements) BTK nitelikli sertifika OID'si "
                            + OID_QC_BTK + " yok. Mevcut ibareler: " + listOrNone(qcStatements) + ".",
                    evidence));
        }
        return findings;
    }

    private static TrComplianceFinding profile(RejectionCode code, String reason, Map<String, Object> evidence) {
        return new TrComplianceFinding(code, reason, Indication.INDETERMINATE,
                SubIndication.CHAIN_CONSTRAINTS_FAILURE, evidence);
    }

    // ---------------------------------------------------------------------------------
    // Sertifika ayrıştırma
    // ---------------------------------------------------------------------------------

    static List<String> keyUsages(X509Certificate certificate) {
        List<String> names = new ArrayList<>();
        boolean[] bits = certificate.getKeyUsage();
        if (bits == null) {
            return names;
        }
        for (int i = 0; i < bits.length && i < KEY_USAGE_NAMES.length; i++) {
            if (bits[i]) {
                names.add(KEY_USAGE_NAMES[i]);
            }
        }
        return names;
    }

    static List<String> extendedKeyUsages(X509Certificate certificate) {
        try {
            List<String> usages = certificate.getExtendedKeyUsage();
            return usages == null ? new ArrayList<String>() : new ArrayList<>(usages);
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    /** Politika OID'si → UserNotice niteleyicisi (boş olmayan metin veya notice reference) var mı. */
    static Map<String, Boolean> certificatePolicies(X509Certificate certificate) {
        Map<String, Boolean> policies = new LinkedHashMap<>();
        ASN1Primitive value = extension(certificate, OID_CERTIFICATE_POLICIES);
        if (value == null) {
            return policies;
        }
        for (PolicyInformation information : CertificatePolicies.getInstance(value).getPolicyInformation()) {
            boolean userNotice = false;
            ASN1Sequence qualifiers = information.getPolicyQualifiers();
            if (qualifiers != null) {
                for (ASN1Encodable encodable : qualifiers) {
                    PolicyQualifierInfo qualifier = PolicyQualifierInfo.getInstance(encodable);
                    if (PolicyQualifierId.id_qt_unotice.equals(qualifier.getPolicyQualifierId())
                            && hasNotice(qualifier.getQualifier())) {
                        userNotice = true;
                    }
                }
            }
            policies.put(information.getPolicyIdentifier().getId(), userNotice);
        }
        return policies;
    }

    private static boolean hasNotice(ASN1Encodable qualifier) {
        try {
            UserNotice notice = UserNotice.getInstance(qualifier);
            DisplayText text = notice.getExplicitText();
            return (text != null && !text.getString().trim().isEmpty()) || notice.getNoticeRef() != null;
        } catch (RuntimeException e) {
            return false;
        }
    }

    static List<String> qcStatementIds(X509Certificate certificate) {
        List<String> ids = new ArrayList<>();
        ASN1Primitive value = extension(certificate, OID_QC_STATEMENTS);
        if (value == null) {
            return ids;
        }
        for (ASN1Encodable encodable : ASN1Sequence.getInstance(value)) {
            ids.add(QCStatement.getInstance(encodable).getStatementId().getId());
        }
        return ids;
    }

    private static ASN1Primitive extension(X509Certificate certificate, String oid) {
        byte[] encoded = certificate.getExtensionValue(oid);
        if (encoded == null) {
            return null;
        }
        try {
            return ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(encoded).getOctets());
        } catch (Exception e) {
            logger.debug("TR uyum: {} uzantısı okunamadı: {}", oid, e.toString());
            return null;
        }
    }

    // ---------------------------------------------------------------------------------
    // DSS diagnostic verisinden girdi çıkarma
    // ---------------------------------------------------------------------------------

    /** Yalnız bütünlüğü sağlam imza zaman damgaları: imzanın var olduğu en erken kanıtlı an. */
    static TimestampWrapper earliestSignatureTimestamp(SignatureWrapper signature) {
        TimestampWrapper earliest = null;
        List<TimestampWrapper> timestamps = signature.getTimestampList();
        if (timestamps == null) {
            return null;
        }
        for (TimestampWrapper timestamp : timestamps) {
            if (timestamp.getType() != TimestampType.SIGNATURE_TIMESTAMP
                    || timestamp.getProductionTime() == null
                    || !timestamp.isSignatureIntact()
                    || !timestamp.isMessageImprintDataIntact()) {
                continue;
            }
            if (earliest == null || timestamp.getProductionTime().before(earliest.getProductionTime())) {
                earliest = timestamp;
            }
        }
        return earliest;
    }

    private static List<RevocationEvidence> revocationEvidence(CertificateWrapper certificate) {
        List<RevocationEvidence> evidence = new ArrayList<>();
        List<CertificateRevocationWrapper> revocations = certificate.getCertificateRevocationData();
        if (revocations == null) {
            return evidence;
        }
        for (CertificateRevocationWrapper revocation : revocations) {
            evidence.add(new RevocationEvidence(revocation.getRevocationType(), revocation.getThisUpdate(),
                    revocation.getNextUpdate(),
                    revocation.getOrigin() != null ? revocation.getOrigin().name() : null));
        }
        return evidence;
    }

    private static Map<String, X509Certificate> indexById(Collection<CertificateToken> tokens) {
        Map<String, X509Certificate> byId = new HashMap<>();
        if (tokens == null) {
            return byId;
        }
        for (CertificateToken token : tokens) {
            if (token != null && token.getCertificate() != null) {
                byId.put("C-" + sha256(token.getCertificate()).toUpperCase(Locale.ROOT), token.getCertificate());
            }
        }
        return byId;
    }

    private static X509Certificate x509(CertificateWrapper wrapper, Map<String, X509Certificate> poolById) {
        byte[] binaries = wrapper.getBinaries();
        if (binaries != null && binaries.length > 0) {
            try {
                return (X509Certificate) CertificateFactory.getInstance("X.509")
                        .generateCertificate(new ByteArrayInputStream(binaries));
            } catch (Exception e) {
                logger.debug("TR uyum: sertifika baytları ayrıştırılamadı ({}): {}", wrapper.getId(), e.toString());
            }
        }
        return poolById.get(wrapper.getId());
    }

    private static String subjectOf(CertificateWrapper wrapper, Map<String, X509Certificate> poolById) {
        X509Certificate certificate = x509(wrapper, poolById);
        return certificate != null ? certificate.getSubjectX500Principal().getName() : wrapper.getCommonName();
    }

    // ---------------------------------------------------------------------------------
    // Yardımcılar
    // ---------------------------------------------------------------------------------

    private static void add(List<TrComplianceFinding> findings, TrComplianceFinding finding) {
        if (finding != null) {
            findings.add(finding);
        }
    }

    private static String listOrNone(Collection<String> values) {
        return values == null || values.isEmpty() ? "yok" : String.join(", ", values);
    }

    static String display(Date date) {
        if (date == null) {
            return "bilinmiyor";
        }
        SimpleDateFormat format = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss", new Locale("tr", "TR"));
        format.setTimeZone(TimeZone.getTimeZone("Europe/Istanbul"));
        return format.format(date);
    }

    private static String iso(Date date) {
        if (date == null) {
            return null;
        }
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT);
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
        return format.format(date);
    }

    private static String sha256(X509Certificate certificate) {
        try {
            StringBuilder hex = new StringBuilder();
            for (byte b : MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded())) {
                hex.append(String.format("%02x", b & 0xff));
            }
            return hex.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /** Bir sertifika için DSS'in topladığı iptal verisinin tarih özeti. */
    static final class RevocationEvidence {
        final RevocationType type;
        final Date thisUpdate;
        final Date nextUpdate;
        final String origin;

        RevocationEvidence(RevocationType type, Date thisUpdate, Date nextUpdate, String origin) {
            this.type = type;
            this.thisUpdate = thisUpdate;
            this.nextUpdate = nextUpdate;
            this.origin = origin;
        }

        boolean isCrl() {
            return type == RevocationType.CRL;
        }
    }
}
