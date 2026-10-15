package io.mersel.dss.verify.api.services.compliance;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.OrphanRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.RelatedRevocationWrapper;
import eu.europa.esig.dss.diagnostic.RevocationRefWrapper;
import eu.europa.esig.dss.diagnostic.RevocationWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import io.mersel.dss.verify.api.models.enums.RejectionCode;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * MA3 {@code force-strict-reference-use=true} eşdeğeri: uzun dönemli imzada (-C / -X /
 * -XL / -A) doğrulama verisinin kendisini denetler.
 *
 * <p>DSS bir sertifika için bulduğu en iyi iptal verisini seçer: imzanın
 * {@code RevocationValues} alanındaki veri bozuk veya süresi dolmuşsa zaman damgası
 * içindeki SİL'i ya da çevrimiçi yeni bir cevabı kullanır ve imzayı geçirir. TÜBİTAK
 * değerlendirmesinde ise imzanın referans verdiği veri kullanılmalıdır; bu sınıf DSS
 * diagnostic verisinden yalnız bu veriyi ({@link #REFERENCED_ORIGINS}) seçip kurallara
 * uygular.</p>
 *
 * <ul>
 *   <li><b>Sertifika referansları ve değerleri</b> — zincirdeki her CA sertifikası (kök
 *       dahil) {@code CompleteCertificateRefs} içinde eşleşen özetle ve
 *       {@code CertificateValues} içinde bulunmalı.</li>
 *   <li><b>İptal referansları</b> — {@code RevocationValues} içindeki her SİL / OCSP cevabı
 *       {@code CompleteRevocationRefs} içinde eşleşen özetle gösterilmeli.</li>
 *   <li><b>İptal verisi</b> — imzacı zincirindeki her sertifika için {@code RevocationValues}
 *       içinde SİL / OCSP bulunmalı; zaman damgası (TSA) zinciri için bu veri zaman
 *       damgasının kendi içinde de olabilir. Referans verilen her iptal verisinin imzası
 *       sağlam, kontrol zamanını kapsıyor ve OCSP sertifikası cevabın üretildiği anda
 *       geçerli olmalı; sertifika kontrol zamanından önce iptal edilmemiş olmalı.</li>
 *   <li><b>Zaman damgası sertifikaları</b> — imza, doğrulama verisi ve içerik zaman
 *       damgalarının TSA zincirindeki CA sertifikaları (kök dahil) imzanın doğrulama
 *       verisinde veya zaman damgasının kendi içinde bulunmalı; yalnız güven deposundaki
 *       kök yetmez. TSA zinciri imzacı zincirinden farklı bir köke bağlanabilir.</li>
 *   <li><b>Zaman damgası</b> — her zaman damgasının imzası ve mesaj özeti sağlam,
 *       TSA sertifikası damga anında geçerli, imzası sağlam ve zinciri güvenilir köke
 *       bağlı olmalı (her imza seviyesinde).</li>
 *   <li><b>Güven kökü</b> — zincirin bağlandığı kendinden imzalı kökün imzası kendi
 *       açık anahtarıyla doğrulanmalı (her imza seviyesinde).</li>
 * </ul>
 *
 * <p>Kurallar saf fonksiyonlardır ({@link CertNode} / {@link RevNode} modelleri);
 * DSS wrapper'larından modele dönüşüm {@link #certNode} ile yapılır.</p>
 */
public final class ValidationDataChecker {

    /** İmzanın referans verdiği iptal verisinin DSS kaynakları (zaman damgası içindeki CMS verisi hariç). */
    static final Set<RevocationOrigin> REFERENCED_ORIGINS = Collections.unmodifiableSet(EnumSet.of(
            RevocationOrigin.REVOCATION_VALUES, RevocationOrigin.ATTRIBUTE_REVOCATION_VALUES,
            RevocationOrigin.TIMESTAMP_VALIDATION_DATA, RevocationOrigin.ANY_VALIDATION_DATA));

    /** {@link #REFERENCED_ORIGINS} karşılığı: imzanın doğrulama verisi olarak taşıdığı sertifikalar. */
    private static final Set<CertificateOrigin> VALIDATION_DATA_CERTIFICATE_ORIGINS = Collections.unmodifiableSet(
            EnumSet.of(CertificateOrigin.CERTIFICATE_VALUES, CertificateOrigin.ATTR_AUTHORITIES_CERT_VALUES,
                    CertificateOrigin.TIMESTAMP_VALIDATION_DATA, CertificateOrigin.ANY_VALIDATION_DATA));

    /**
     * {@code nextUpdate} taşımayan OCSP cevabı kontrol zamanından en fazla bu kadar önce
     * üretilmiş olabilir (TSA / OCSP saat farkı, damgadan hemen önce alınan cevap). İmzacı
     * politikasının 24 saatlik RevocationFreshness değeriyle aynıdır.
     */
    static final long OCSP_FRESHNESS_TOLERANCE_MILLIS = 24L * 60 * 60 * 1000;

    /** OCSP responder sertifikasının iptal verisi aranırken izlenen en fazla derinlik. */
    private static final int MAX_RESPONDER_DEPTH = 2;

    private static final Provider BC = new BouncyCastleProvider();

    private ValidationDataChecker() {
    }

    /** Sertifikanın doğrulama verisi içindeki rolü; mesajları ve kontrol zamanını belirler. */
    enum Role {
        SIGNER("İmzacı sertifikası"),
        CA("Alt kök sertifikası"),
        TSA("Zaman damgası sertifikası"),
        TSA_CA("Zaman damgası alt kök sertifikası"),
        OCSP_RESPONDER("OCSP sertifikası");

        final String label;

        Role(String label) {
            this.label = label;
        }
    }

    // ---------------------------------------------------------------------------------
    // Model
    // ---------------------------------------------------------------------------------

    /** Kuralların ihtiyaç duyduğu sertifika bilgisi. */
    static final class CertNode {
        final String id;
        final String subject;
        final Date notBefore;
        final Date notAfter;
        final boolean trusted;
        final boolean selfIssued;
        final boolean signatureIntact;
        final boolean ocspNoCheck;
        final List<RevNode> revocations = new ArrayList<>();

        CertNode(String id, String subject, Date notBefore, Date notAfter, boolean trusted,
                 boolean selfIssued, boolean signatureIntact, boolean ocspNoCheck) {
            this.id = id;
            this.subject = subject;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.trusted = trusted;
            this.selfIssued = selfIssued;
            this.signatureIntact = signatureIntact;
            this.ocspNoCheck = ocspNoCheck;
        }

        boolean isAnchor() {
            return trusted || selfIssued;
        }

        boolean validAt(Date time) {
            return time == null || ((notBefore == null || !time.before(notBefore))
                    && (notAfter == null || !time.after(notAfter)));
        }
    }

    /** Bir sertifika hakkındaki iptal verisi (SİL veya OCSP cevabı). */
    static final class RevNode {
        final String id;
        final RevocationType type;
        /** İmzanın referans verdiği veri mi ({@link #REFERENCED_ORIGINS}). */
        final boolean referenced;
        final Date productionDate;
        final Date thisUpdate;
        final Date nextUpdate;
        final boolean signatureIntact;
        final CertificateStatus status;
        final Date revocationDate;
        /** OCSP cevabını imzalayan sertifika; SİL için {@code null}. */
        final CertNode responder;

        RevNode(String id, RevocationType type, boolean referenced, Date productionDate, Date thisUpdate,
                Date nextUpdate, boolean signatureIntact, CertificateStatus status, Date revocationDate,
                CertNode responder) {
            this.id = id;
            this.type = type;
            this.referenced = referenced;
            this.productionDate = productionDate;
            this.thisUpdate = thisUpdate;
            this.nextUpdate = nextUpdate;
            this.signatureIntact = signatureIntact;
            this.status = status;
            this.revocationDate = revocationDate;
            this.responder = responder;
        }

        boolean isCrl() {
            return type == RevocationType.CRL;
        }

        String label() {
            return isCrl() ? "SİL" : "OCSP cevabı";
        }

        /** Tamlayan hali: "SİL'in" / "OCSP cevabının". */
        String genitive() {
            return isCrl() ? "SİL'in" : "OCSP cevabının";
        }
    }

    /** Doğrulamada kullanılan ama kontrol zamanından sonra iptal edilmiş sertifika (arşiv gerekçesi). */
    public static final class LaterRevocation {
        private final String subject;
        private final String role;
        private final Date revocationDate;
        private final Date controlTime;

        LaterRevocation(String subject, String role, Date revocationDate, Date controlTime) {
            this.subject = subject;
            this.role = role;
            this.revocationDate = revocationDate;
            this.controlTime = controlTime;
        }

        public String getSubject() {
            return subject;
        }

        public String getRole() {
            return role;
        }

        public Date getRevocationDate() {
            return revocationDate;
        }

        public Date getControlTime() {
            return controlTime;
        }
    }

    /** Bir sertifikanın iptal değerlendirmesi: ret bulgusu ve/veya sonradan iptal kayıtları. */
    static final class RevocationOutcome {
        final TrComplianceFinding finding;
        final List<LaterRevocation> laterRevocations;
        /** {@link RejectionCode#MDSS_TR_CERT_REVOKED} bulgusunda iptal tarihi. */
        final Date revokedAt;

        RevocationOutcome(TrComplianceFinding finding, List<LaterRevocation> laterRevocations) {
            this(finding, laterRevocations, null);
        }

        RevocationOutcome(TrComplianceFinding finding, List<LaterRevocation> laterRevocations, Date revokedAt) {
            this.finding = finding;
            this.laterRevocations = laterRevocations;
            this.revokedAt = revokedAt;
        }
    }

    /** Bir CompleteCertificateRefs referansının eşleşme bilgisi. */
    static final class RefMatch {
        final boolean digestPresent;
        final boolean digestMatch;

        RefMatch(boolean digestPresent, boolean digestMatch) {
            this.digestPresent = digestPresent;
            this.digestMatch = digestMatch;
        }
    }

    // ---------------------------------------------------------------------------------
    // İmza seviyesinde giriş noktaları
    // ---------------------------------------------------------------------------------

    /**
     * İmzanın doğrulama verisi bulgularını üretir.
     *
     * @param strictReference  sıkı referans kurallarını (sertifika referansları, iptal verisi)
     *                         uygula; zaman damgası ve güven kökü kuralları her durumda çalışır
     * @param referencedCrls   imzanın RevocationValues alanındaki ham SİL'ler; DSS'in hiçbir
     *                         sertifikaya bağlayamadığı (imzası bozuk) SİL'i adlandırmak için
     * @param timestampCrls    zaman damgalarının içindeki ham SİL'ler (TSA zinciri için)
     * @param signerControlTime imzacı zinciri için kontrol zamanı (imza zaman damgası, yoksa
     *                         doğrulama zamanı)
     */
    static List<TrComplianceFinding> evaluate(SignatureWrapper signature, boolean strictReference,
                                              Collection<byte[]> referencedCrls, Collection<byte[]> timestampCrls,
                                              Date signerControlTime, String signerControlSource) {
        List<TrComplianceFinding> findings = new ArrayList<>();
        Set<String> referencedIds = referencedRevocationIds(signature);
        boolean hasReferencedData = hasReferencedRevocationData(signature);

        List<CertificateWrapper> chain = signature.getCertificateChain();
        add(findings, checkTrustAnchor(nodes(chain, referencedIds), "İmzacı sertifika zincirinin"));

        if (strictReference && hasCompleteCertificateRefs(signature) && chain != null) {
            findings.addAll(checkCertificateRefs(nodes(chain, referencedIds), refMatches(signature),
                    "Kök sertifikası", "Alt kök sertifikası"));
        }
        if (strictReference && findings.isEmpty() && chain != null && hasCertificateValues(signature)) {
            findings.addAll(checkCertificateValues(nodes(chain, referencedIds), certificateValueIds(signature)));
        }
        if (strictReference && findings.isEmpty() && hasReferencedData) {
            add(findings, checkRevocationRefs(revocationRefs(signature)));
        }

        List<X509CRL> crls = parseCrls(referencedCrls);
        List<X509CRL> tsaCrls = new ArrayList<>(crls);
        tsaCrls.addAll(parseCrls(timestampCrls));
        // Sıkı mod: yalnız RevocationValues, her veri kabul edilebilir ve veri zorunlu.
        // Esnek mod (RevocationValues yok veya sıkı referans kapalı): DSS'in bulduğu tüm veri
        // (çevrimiçi dahil), biri yeterli; veri yokluğu tek başına ret nedeni değildir.
        boolean strict = strictReference && hasReferencedData;
        Set<String> chainReferenced = strict ? referencedIds : signerChainIds(signature);
        if (findings.isEmpty() && chain != null) {
            for (int i = 0; i < chain.size(); i++) {
                CertNode certificate = certNode(chain.get(i), chainReferenced, 0);
                X509Certificate issuer = i + 1 < chain.size() ? x509(chain.get(i + 1)) : null;
                RevocationOutcome outcome = evaluateRevocation(certificate, i == 0 ? Role.SIGNER : Role.CA,
                        signerControlTime, signerControlSource, orphanCrlsOf(issuer, strict ? crls : tsaCrls),
                        issuer, strict, strict);
                if (outcome.finding != null) {
                    findings.add(outcome.finding);
                    break;
                }
            }
        }

        List<TimestampWrapper> timestamps = signature.getTimestampList();
        // İmzacı zinciri zaten reddedildiyse zaman damgalarında yalnız bütünlük denetlenir;
        // aynı eksikliğin damga tarafındaki yansıması ikinci bir bulgu üretmez.
        boolean chainRejected = !findings.isEmpty();
        boolean certificateRefs = strictReference && !chainRejected && hasCompleteCertificateRefs(signature);
        Set<String> validationDataCertificates = certificateRefs
                ? validationDataCertificateIds(signature) : Collections.<String>emptySet();
        if (timestamps != null) {
            for (TimestampWrapper timestamp : timestamps) {
                TrComplianceFinding finding = checkTimestamp(timestamp, referencedIds);
                if (finding == null && !chainRejected && requiresReferencedRevocation(timestamp.getType())) {
                    finding = checkTimestampRevocation(timestamp,
                            strict ? timestampReferencedIds(timestamp, referencedIds) : null, tsaCrls, strict);
                }
                if (finding == null && certificateRefs && requiresReferencedRevocation(timestamp.getType())) {
                    finding = checkTimestampCertificates(timestamp, validationDataCertificates);
                }
                if (finding != null) {
                    findings.add(finding);
                    break;
                }
            }
        }
        return findings;
    }

    /**
     * Doğrulamada kullanılan ve kontrol zamanından <em>sonra</em> iptal edilmiş, imzacı
     * dışındaki sertifikalar: alt kök, OCSP sertifikası, zaman damgası sertifikası. İmza
     * geçerlidir ancak bu kanıt zamanla doğrulanamaz hale gelir; imza arşivlenmelidir.
     * İmza referans verisi taşıyorsa yalnız o veri, taşımıyorsa DSS'in bulduğu tüm veri
     * değerlendirilir.
     */
    public static List<LaterRevocation> laterRevocations(SignatureWrapper signature, Date signerControlTime) {
        List<LaterRevocation> result = new ArrayList<>();
        if (signature == null) {
            return result;
        }
        Set<String> referencedIds = referencedRevocationIds(signature);
        boolean referencedOnly = !referencedIds.isEmpty();
        List<CertificateWrapper> chain = signature.getCertificateChain();
        if (chain != null) {
            Set<String> chainIds = referencedOnly ? referencedIds : signerChainIds(signature);
            for (int i = 0; i < chain.size(); i++) {
                CertNode node = certNode(chain.get(i), chainIds, 0);
                result.addAll(evaluateRevocation(node, i == 0 ? Role.SIGNER : Role.CA, signerControlTime,
                        null, Collections.<X509CRL>emptyList(), null, false, false).laterRevocations);
            }
        }
        List<TimestampWrapper> timestamps = signature.getTimestampList();
        if (timestamps != null) {
            for (TimestampWrapper timestamp : timestamps) {
                if (!requiresReferencedRevocation(timestamp.getType())) {
                    continue;
                }
                List<CertificateWrapper> tsaChain = timestamp.getCertificateChain();
                Set<String> tsaReferenced = referencedOnly ? timestampReferencedIds(timestamp, referencedIds) : null;
                for (int i = 0; tsaChain != null && i < tsaChain.size(); i++) {
                    CertNode node = certNode(tsaChain.get(i), tsaReferenced, 0);
                    result.addAll(evaluateRevocation(node, i == 0 ? Role.TSA : Role.TSA_CA,
                            timestamp.getProductionTime(), null, Collections.<X509CRL>emptyList(), null, false, false)
                            .laterRevocations);
                }
            }
        }
        return dedupe(result);
    }

    // ---------------------------------------------------------------------------------
    // Kurallar
    // ---------------------------------------------------------------------------------

    /** Zincirin son sertifikası kendinden imzalı bir kök ise imzası sağlam olmalı. */
    static TrComplianceFinding checkTrustAnchor(List<CertNode> chain, String context) {
        if (chain == null || chain.isEmpty()) {
            return null;
        }
        CertNode last = chain.get(chain.size() - 1);
        if (!last.selfIssued || last.signatureIntact) {
            return null;
        }
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("certificateSubject", last.subject);
        evidence.put("trusted", last.trusted);
        return new TrComplianceFinding(RejectionCode.MDSS_TR_TRUST_ANCHOR_SIGNATURE_INVALID,
                context + " bağlandığı kök sertifikasının ('" + last.subject + "') imzası, kendi açık "
                        + "anahtarıyla doğrulanamadı; kök sertifikası bozuk veya sahte. Güven deposunda "
                        + "bulunması bu sertifikayı geçerli kılmaz.",
                Indication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, evidence);
    }

    /**
     * Zincirdeki imzacı dışındaki her sertifika (alt kökler ve kök) CompleteCertificateRefs
     * içinde özeti eşleşen bir referansla bulunmalı.
     *
     * @param refs sertifika kimliği → o sertifikayı gösteren CompleteCertificateRefs referansları
     */
    static List<TrComplianceFinding> checkCertificateRefs(List<CertNode> chain, Map<String, List<RefMatch>> refs,
                                                          String rootLabel, String intermediateLabel) {
        List<TrComplianceFinding> findings = new ArrayList<>();
        for (int i = 1; i < chain.size(); i++) {
            CertNode certificate = chain.get(i);
            String label = (i == chain.size() - 1 && certificate.isAnchor()) ? rootLabel : intermediateLabel;
            List<RefMatch> matches = refs.get(certificate.id);
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("certificateSubject", certificate.subject);
            evidence.put("certificateId", certificate.id);
            if (matches == null || matches.isEmpty()) {
                findings.add(new TrComplianceFinding(RejectionCode.MDSS_TR_CERT_REF_MISSING,
                        label + " ('" + certificate.subject + "') referans bilgisi imzanın sertifika "
                                + "referanslarında (CompleteCertificateRefs) yok. Eksik bilginin "
                                + "tamamlanması gerekmektedir.",
                        Indication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, evidence));
                continue;
            }
            boolean matched = false;
            for (RefMatch match : matches) {
                matched |= !match.digestPresent || match.digestMatch;
            }
            if (!matched) {
                findings.add(new TrComplianceFinding(RejectionCode.MDSS_TR_CERT_REF_INVALID,
                        label + " ('" + certificate.subject + "') referans bilgisi hatalı: imzanın "
                                + "sertifika referanslarındaki (CompleteCertificateRefs) özet değeri "
                                + "sertifikayla eşleşmiyor.",
                        Indication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, evidence));
            }
        }
        return findings;
    }

    /**
     * Uzun dönemli imzada (CertificateValues var) zincirdeki imzacı dışındaki her sertifika
     * (alt kökler ve kök) CertificateValues içinde bulunmalı; güven deposu veya AIA ile
     * bulunan sertifika referans verisinin yerini tutmaz.
     */
    static List<TrComplianceFinding> checkCertificateValues(List<CertNode> chain, Set<String> certificateValues) {
        List<TrComplianceFinding> findings = new ArrayList<>();
        for (int i = 1; i < chain.size(); i++) {
            CertNode certificate = chain.get(i);
            if (certificateValues.contains(certificate.id)) {
                continue;
            }
            String label = (i == chain.size() - 1 && certificate.isAnchor()) ? "Kök sertifikası" : "Alt kök sertifikası";
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("certificateSubject", certificate.subject);
            evidence.put("certificateId", certificate.id);
            findings.add(new TrComplianceFinding(RejectionCode.MDSS_TR_CERT_VALUE_MISSING,
                    label + " ('" + certificate.subject + "') imzanın sertifika değerlerinde (CertificateValues) "
                            + "yok. Sıkı referans kullanımında güven deposu veya AIA ile bulunan sertifika "
                            + "kullanılmaz. Eksik bilginin tamamlanması gerekmektedir.",
                    Indication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, evidence));
        }
        return findings;
    }

    /** RevocationValues ile CompleteRevocationRefs arasındaki eşleşme özeti. */
    static final class RevocationRefs {
        /** Referansı olmayan iptal değerleri (tür + düzenleyici + tarih). */
        final List<String> unreferencedValues = new ArrayList<>();
        /** RevocationValues içinde değeri olmayan referanslar (tür, biliniyorsa düzenleyici). */
        final List<String> valuelessReferences = new ArrayList<>();
        boolean present;
    }

    /**
     * İmza CompleteRevocationRefs taşıyorsa RevocationValues içindeki her SİL / OCSP cevabı
     * bir referansla eşleşmeli ve her referans bir değeri göstermeli: referansı olmayan değer
     * "referans eksik", değeri olmayan referans "değer eksik", ikisi birden (değiştirilmiş
     * değer veya yanlış özet) "hatalı" olarak raporlanır.
     */
    static TrComplianceFinding checkRevocationRefs(RevocationRefs refs) {
        if (refs == null || !refs.present
                || (refs.unreferencedValues.isEmpty() && refs.valuelessReferences.isEmpty())) {
            return null;
        }
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("unreferencedValues", refs.unreferencedValues);
        evidence.put("unmatchedReferences", refs.valuelessReferences);
        if (refs.unreferencedValues.isEmpty()) {
            return new TrComplianceFinding(RejectionCode.MDSS_TR_REVOCATION_DATA_MISSING,
                    "İptal değeri eksik: iptal referanslarında (CompleteRevocationRefs) gösterilen "
                            + String.join(", ", refs.valuelessReferences) + " imzanın iptal değerlerinde "
                            + "(RevocationValues) yok. Eksik bilginin tamamlanması gerekmektedir.",
                    Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence);
        }
        if (refs.valuelessReferences.isEmpty()) {
            return new TrComplianceFinding(RejectionCode.MDSS_TR_REVOCATION_REF_MISSING,
                    "İptal referans bilgisi eksik: imzanın iptal değerlerindeki (RevocationValues) "
                            + String.join(", ", refs.unreferencedValues) + " için iptal referanslarında "
                            + "(CompleteRevocationRefs) referans bilgisi yok. Eksik bilginin tamamlanması "
                            + "gerekmektedir.",
                    Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence);
        }
        return new TrComplianceFinding(RejectionCode.MDSS_TR_REVOCATION_REF_INVALID,
                "İptal referans bilgisi hatalı: iptal değerlerindeki (RevocationValues) "
                        + String.join(", ", refs.unreferencedValues) + " iptal referanslarında "
                        + "(CompleteRevocationRefs) eşleşen bir özetle gösterilmiyor. İptal değeri "
                        + "değiştirilmiş veya referans yanlış hesaplanmış.",
                Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence);
    }

    /**
     * Bir sertifikayı imzanın referans verdiği iptal verisiyle değerlendirir.
     *
     * <p>Referans verilen her iptal verisi kabul edilebilir olmalı: imzası sağlam; SİL ise
     * {@code nextUpdate} kontrol zamanından önce dolmamış; OCSP cevabı ise kontrol zamanında
     * veya sonrasında üretilmiş (ya da {@code nextUpdate}'i kontrol zamanını kapsıyor) ve
     * imzalayan sertifika cevabın üretildiği anda geçerli ve iptal edilmemiş. Veri
     * sertifikanın kontrol zamanında veya öncesinde iptal edildiğini söylüyorsa ret; sonra
     * iptal edildiyse (imzacı hariç) arşiv gerekçesi olarak kaydedilir.</p>
     *
     * @param orphanCrls düzenleyicinin DN'iyle eşleşen ama DSS'in sertifikaya bağlayamadığı SİL'ler
     * @param requireAll {@code true}: referans verilen her iptal verisi kabul edilebilir olmalı
     *                   (sıkı mod, imzacı zinciri); {@code false}: en az biri yeterli (TSA zinciri,
     *                   esnek mod)
     * @param requirePresence {@code true}: iptal verisi yoksa ret (sıkı mod); {@code false}: veri
     *                   yokluğu tek başına ret nedeni değildir, karar DSS'indir (esnek mod)
     */
    static RevocationOutcome evaluateRevocation(CertNode certificate, Role role, Date controlTime,
                                                String controlSource, List<X509CRL> orphanCrls,
                                                X509Certificate issuer, boolean requireAll,
                                                boolean requirePresence) {
        List<LaterRevocation> later = new ArrayList<>();
        if (certificate == null || certificate.isAnchor()
                || (role == Role.OCSP_RESPONDER && certificate.ocspNoCheck)) {
            return new RevocationOutcome(null, later);
        }
        List<RevNode> referenced = new ArrayList<>();
        for (RevNode revocation : certificate.revocations) {
            if (revocation.referenced) {
                referenced.add(revocation);
            }
        }
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("certificateSubject", certificate.subject);
        evidence.put("role", role.name());
        evidence.put("controlTime", TrComplianceChecker.iso(controlTime));
        if (controlSource != null) {
            evidence.put("controlTimeSource", controlSource);
        }
        if (referenced.isEmpty()) {
            if (role == Role.OCSP_RESPONDER) {
                return new RevocationOutcome(null, later);
            }
            X509CRL forged = firstUnverifiableCrl(orphanCrls, issuer);
            if (forged != null) {
                evidence.put("crlIssuer", forged.getIssuerX500Principal().getName());
                evidence.put("crlThisUpdate", TrComplianceChecker.iso(forged.getThisUpdate()));
                return new RevocationOutcome(new TrComplianceFinding(
                        RejectionCode.MDSS_TR_REVOCATION_SIGNATURE_INVALID,
                        role.label + "nın ('" + certificate.subject + "') iptal kontrolü için "
                                + (role == Role.TSA || role == Role.TSA_CA ? "zaman damgasında" : "imzada")
                                + " bulunan SİL'in ('" + forged.getIssuerX500Principal().getName() + "', "
                                + TrComplianceChecker.display(forged.getThisUpdate()) + ") imzası, düzenleyici "
                                + "sertifikanın açık anahtarıyla doğrulanamadı; SİL bozuk veya sahte.",
                        Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence), later);
            }
            if (!requirePresence) {
                return new RevocationOutcome(null, later);
            }
            evidence.put("otherRevocationSources", otherSources(certificate));
            return new RevocationOutcome(new TrComplianceFinding(RejectionCode.MDSS_TR_REVOCATION_DATA_MISSING,
                    role.label + "nın ('" + certificate.subject + "') iptal bilgisi (SİL / OCSP) "
                            + (role == Role.TSA || role == Role.TSA_CA
                            ? "ne imzanın RevocationValues alanında ne de zaman damgasının içinde var."
                            : "imzanın RevocationValues alanında yok. Sıkı referans kullanımında çevrimiçi veya "
                            + "zaman damgası içindeki veri kullanılmaz.")
                            + " Eksik bilginin tamamlanması gerekmektedir.",
                    Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence), later);
        }

        // Sıkı referans: imzacı zincirinde referans verilen her iptal verisi kabul edilebilir
        // olmalı; başka bir geçerli veri bozuk / süresi dolmuş referans verisini ikame etmez.
        List<RevNode> acceptable = new ArrayList<>();
        TrComplianceFinding firstProblem = null;
        int firstPriority = Integer.MAX_VALUE;
        for (RevNode revocation : referenced) {
            Problem problem = problem(certificate, role, revocation, controlTime, evidence, later);
            if (problem == null) {
                acceptable.add(revocation);
            } else if (problem.priority < firstPriority) {
                firstProblem = problem.finding;
                firstPriority = problem.priority;
            }
        }
        if (firstProblem != null && (requireAll || acceptable.isEmpty())) {
            return new RevocationOutcome(firstProblem, later);
        }
        for (RevNode revocation : acceptable) {
            if (revocation.status == null || !revocation.status.isRevoked()) {
                continue;
            }
            if (revocation.revocationDate == null || controlTime == null
                    || !revocation.revocationDate.after(controlTime)) {
                evidence.put("revocationDate", TrComplianceChecker.iso(revocation.revocationDate));
                evidence.put("revocationSource", revocation.label());
                return new RevocationOutcome(new TrComplianceFinding(RejectionCode.MDSS_TR_CERT_REVOKED,
                        role.label + " ('" + certificate.subject + "') "
                                + TrComplianceChecker.display(revocation.revocationDate) + " tarihinde iptal "
                                + "edilmiş (" + revocation.label() + "); kontrol zamanı "
                                + TrComplianceChecker.display(controlTime)
                                + (controlSource != null ? " (" + controlSource + ")" : "") + ". İptal "
                                + "edilmiş sertifikayla oluşturulan imza geçerli değildir.",
                        Indication.INDETERMINATE,
                        role == Role.CA || role == Role.TSA_CA
                                ? SubIndication.REVOKED_CA_NO_POE : SubIndication.REVOKED_NO_POE,
                        evidence), later, revocation.revocationDate);
            }
            if (role != Role.SIGNER) {
                later.add(new LaterRevocation(certificate.subject, role.label, revocation.revocationDate, controlTime));
            }
        }
        return new RevocationOutcome(null, later);
    }

    private static final class Problem {
        final TrComplianceFinding finding;
        final int priority;

        Problem(TrComplianceFinding finding, int priority) {
            this.finding = finding;
            this.priority = priority;
        }
    }

    /** Referans verilen tek bir iptal verisinin kabul edilemezlik nedeni; kabul edilebilirse {@code null}. */
    private static Problem problem(CertNode certificate, Role role, RevNode revocation, Date controlTime,
                                   Map<String, Object> baseEvidence, List<LaterRevocation> later) {
        Map<String, Object> evidence = new LinkedHashMap<>(baseEvidence);
        evidence.put("revocationType", revocation.type != null ? revocation.type.name() : null);
        evidence.put("thisUpdate", TrComplianceChecker.iso(revocation.thisUpdate));
        evidence.put("nextUpdate", TrComplianceChecker.iso(revocation.nextUpdate));
        evidence.put("productionDate", TrComplianceChecker.iso(revocation.productionDate));
        String subject = role.label + "nın ('" + certificate.subject + "') iptal kontrolünde kullanılan ";

        if (!revocation.signatureIntact) {
            return new Problem(new TrComplianceFinding(RejectionCode.MDSS_TR_REVOCATION_SIGNATURE_INVALID,
                    subject + revocation.genitive() + " imzası doğrulanamadı; " + revocation.label()
                            + " bozuk veya sahte.",
                    Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence), 1);
        }
        if (controlTime != null && revocation.isCrl()
                && revocation.nextUpdate != null && revocation.nextUpdate.before(controlTime)) {
            return new Problem(new TrComplianceFinding(RejectionCode.MDSS_TR_CRL_EXPIRED,
                    subject + "SİL'in geçerlilik süresi dolmuş: SİL "
                            + TrComplianceChecker.display(revocation.thisUpdate) + " tarihinde yayımlanmış, bir "
                            + "sonraki yayın tarihi (nextUpdate) " + TrComplianceChecker.display(revocation.nextUpdate)
                            + "; kontrol zamanı " + TrComplianceChecker.display(controlTime) + ". Süresi dolmuş "
                            + "SİL ile sertifikanın iptal durumu doğrulanamaz.",
                    Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence), 2);
        }
        if (controlTime != null && !revocation.isCrl() && !ocspCovers(revocation, controlTime)) {
            return new Problem(new TrComplianceFinding(RejectionCode.MDSS_TR_OCSP_EXPIRED,
                    subject + "OCSP cevabının süresi dolmuş: cevap " + TrComplianceChecker.display(revocation.thisUpdate)
                            + " anındaki durumu bildiriyor"
                            + (revocation.nextUpdate != null
                            ? " ve " + TrComplianceChecker.display(revocation.nextUpdate) + " tarihine kadar geçerli"
                            : "")
                            + "; kontrol zamanı " + TrComplianceChecker.display(controlTime) + ". Bu cevap kontrol "
                            + "zamanındaki iptal durumunu kanıtlamaz.",
                    Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence), 2);
        }
        CertNode responder = revocation.responder;
        if (!revocation.isCrl() && responder != null && !responder.trusted) {
            Date produced = revocation.productionDate;
            evidence.put("responderSubject", responder.subject);
            evidence.put("responderNotAfter", TrComplianceChecker.iso(responder.notAfter));
            if (!responder.signatureIntact) {
                return new Problem(new TrComplianceFinding(RejectionCode.MDSS_TR_OCSP_RESPONDER_INVALID,
                        subject + "OCSP cevabını imzalayan sertifikanın ('" + responder.subject + "') imzası, "
                                + "onu düzenleyen sertifikayla doğrulanamadı; OCSP sertifikası bozuk veya sahte.",
                        Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence), 0);
            }
            if (!responder.validAt(produced)) {
                return new Problem(new TrComplianceFinding(RejectionCode.MDSS_TR_OCSP_RESPONDER_INVALID,
                        subject + "OCSP cevabını imzalayan sertifika ('" + responder.subject + "') cevabın "
                                + "üretildiği anda (" + TrComplianceChecker.display(produced) + ") geçerli "
                                + "değil: geçerlilik aralığı " + TrComplianceChecker.display(responder.notBefore)
                                + " – " + TrComplianceChecker.display(responder.notAfter) + ".",
                        Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence), 0);
            }
            RevocationOutcome responderOutcome = evaluateRevocation(responder, Role.OCSP_RESPONDER, produced,
                    "OCSP cevabının üretim zamanı", Collections.<X509CRL>emptyList(), null, false, false);
            later.addAll(responderOutcome.laterRevocations);
            if (responderOutcome.finding != null
                    && responderOutcome.finding.getCode() == RejectionCode.MDSS_TR_CERT_REVOKED) {
                evidence.put("responderRevocationDate", TrComplianceChecker.iso(responderOutcome.revokedAt));
                return new Problem(new TrComplianceFinding(RejectionCode.MDSS_TR_OCSP_RESPONDER_INVALID,
                        subject + "OCSP cevabını imzalayan sertifika ('" + responder.subject + "') "
                                + TrComplianceChecker.display(responderOutcome.revokedAt) + " tarihinde, yani "
                                + "cevap üretilmeden (" + TrComplianceChecker.display(produced) + ") önce iptal "
                                + "edilmiş. İptal edilmiş OCSP sertifikasının cevabı kullanılamaz.",
                        Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence), 0);
            }
        }
        if (revocation.status != null && !revocation.status.isKnown()) {
            return new Problem(new TrComplianceFinding(RejectionCode.MDSS_TR_REVOCATION_DATA_MISSING,
                    subject + revocation.label() + " sertifikanın durumunu bilinmiyor (unknown) olarak bildiriyor.",
                    Indication.INDETERMINATE, SubIndication.TRY_LATER, evidence), 3);
        }
        return null;
    }

    /**
     * OCSP cevabı kontrol zamanındaki durumu kanıtlıyor mu: {@code nextUpdate} varsa kontrol
     * zamanını kapsamalı; yoksa cevap kontrol zamanından en fazla
     * {@link #OCSP_FRESHNESS_TOLERANCE_MILLIS} önce veya sonra üretilmiş olmalı.
     */
    static boolean ocspCovers(RevNode revocation, Date controlTime) {
        if (revocation.nextUpdate != null) {
            return !revocation.nextUpdate.before(controlTime);
        }
        Date issued = revocation.thisUpdate != null ? revocation.thisUpdate : revocation.productionDate;
        return issued != null
                && !issued.before(new Date(controlTime.getTime() - OCSP_FRESHNESS_TOLERANCE_MILLIS));
    }

    /**
     * Zaman damgasının kendisini ve TSA sertifikasını denetler: imza, mesaj özeti, TSA
     * sertifikasının damga anında geçerliliği, zincir imzaları ve güven köküne bağlantı.
     */
    static TrComplianceFinding checkTimestamp(TimestampWrapper timestamp, Set<String> referencedIds) {
        Date produced = timestamp.getProductionTime();
        CertificateWrapper tsa = timestamp.getSigningCertificate();
        String name = tsName(timestamp, tsa);
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("timestampId", timestamp.getId());
        evidence.put("timestampType", timestamp.getType() != null ? timestamp.getType().name() : null);
        evidence.put("productionTime", TrComplianceChecker.iso(produced));
        if (tsa != null) {
            evidence.put("tsaSubject", tsa.getCertificateDN());
        }
        if (!timestamp.isSignatureIntact()) {
            return new TrComplianceFinding(RejectionCode.MDSS_TR_TIMESTAMP_INVALID,
                    name + " imzası doğrulanamadı; zaman damgası bozuk veya sahte.",
                    Indication.INDETERMINATE, SubIndication.SIG_CONSTRAINTS_FAILURE, evidence);
        }
        if (!timestamp.isMessageImprintDataFound() || !timestamp.isMessageImprintDataIntact()) {
            return new TrComplianceFinding(RejectionCode.MDSS_TR_TIMESTAMP_INVALID,
                    name + " mesaj özeti damgalanan veriyle eşleşmiyor; zaman damgası bu imzaya ait değil "
                            + "veya damgalanan veri değiştirilmiş.",
                    Indication.INDETERMINATE, SubIndication.SIG_CONSTRAINTS_FAILURE, evidence);
        }
        if (tsa == null) {
            return new TrComplianceFinding(RejectionCode.MDSS_TR_TSA_CERT_INVALID,
                    name + " sertifikası bulunamadı.",
                    Indication.INDETERMINATE, SubIndication.SIG_CONSTRAINTS_FAILURE, evidence);
        }
        List<CertNode> chain = nodes(timestamp.getCertificateChain(), referencedIds);
        for (CertNode certificate : chain) {
            if (!certificate.isAnchor() && !certificate.signatureIntact) {
                evidence.put("certificateSubject", certificate.subject);
                return new TrComplianceFinding(RejectionCode.MDSS_TR_TSA_CERT_INVALID,
                        name + " zincirindeki '" + certificate.subject + "' sertifikasının imzası, onu düzenleyen "
                                + "sertifikayla doğrulanamadı; sertifika imzası bozuk veya sahte.",
                        Indication.INDETERMINATE, SubIndication.SIG_CONSTRAINTS_FAILURE, evidence);
            }
        }
        if (produced != null && ((tsa.getNotAfter() != null && produced.after(tsa.getNotAfter()))
                || (tsa.getNotBefore() != null && produced.before(tsa.getNotBefore())))) {
            evidence.put("tsaNotBefore", TrComplianceChecker.iso(tsa.getNotBefore()));
            evidence.put("tsaNotAfter", TrComplianceChecker.iso(tsa.getNotAfter()));
            return new TrComplianceFinding(RejectionCode.MDSS_TR_TSA_CERT_INVALID,
                    name + " sertifikası ('" + tsa.getCertificateDN() + "') damga anında ("
                            + TrComplianceChecker.display(produced) + ") geçerli değil: geçerlilik aralığı "
                            + TrComplianceChecker.display(tsa.getNotBefore()) + " – "
                            + TrComplianceChecker.display(tsa.getNotAfter()) + ".",
                    Indication.INDETERMINATE, SubIndication.SIG_CONSTRAINTS_FAILURE, evidence);
        }
        TrComplianceFinding anchor = checkTrustAnchor(chain, name + " zincirinin");
        if (anchor != null) {
            return anchor;
        }
        if (!timestamp.isTrustedChain()) {
            return new TrComplianceFinding(RejectionCode.MDSS_TR_TSA_CERT_INVALID,
                    name + " sertifikası ('" + tsa.getCertificateDN() + "') güvenilir bir köke bağlanamıyor.",
                    Indication.INDETERMINATE, SubIndication.SIG_CONSTRAINTS_FAILURE, evidence);
        }
        return null;
    }

    /**
     * TSA zincirindeki sertifikaları damga anı için değerlendirir.
     *
     * @param referencedIds sıkı modda imzanın ve damganın kendi verisi; {@code null}: DSS'in
     *                      bulduğu tüm veri (esnek mod)
     */
    private static TrComplianceFinding checkTimestampRevocation(TimestampWrapper timestamp, Set<String> referencedIds,
                                                                List<X509CRL> crls, boolean requirePresence) {
        List<CertificateWrapper> chain = timestamp.getCertificateChain();
        String name = tsName(timestamp, timestamp.getSigningCertificate());
        for (int i = 0; chain != null && i < chain.size(); i++) {
            CertNode certificate = certNode(chain.get(i), referencedIds, 0);
            X509Certificate issuer = i + 1 < chain.size() ? x509(chain.get(i + 1)) : null;
            RevocationOutcome outcome = evaluateRevocation(certificate, i == 0 ? Role.TSA : Role.TSA_CA,
                    timestamp.getProductionTime(), "zaman damgasının üretim zamanı", orphanCrlsOf(issuer, crls),
                    issuer, false, requirePresence);
            if (outcome.finding != null) {
                return outcome.finding;
            }
        }
        return null;
    }

    /**
     * TSA zinciri için referans verilen iptal verisi: imzanın RevocationValues verisi ve
     * zaman damgasının kendi içindeki (CMS) SİL / OCSP.
     */
    static Set<String> timestampReferencedIds(TimestampWrapper timestamp, Set<String> signatureReferenced) {
        Set<String> ids = new HashSet<>(signatureReferenced);
        if (timestamp.foundRevocations() != null) {
            for (RelatedRevocationWrapper revocation : timestamp.foundRevocations().getRelatedRevocationData()) {
                ids.add(revocation.getId());
            }
        }
        return ids;
    }

    /**
     * TSA zincirindeki CA sertifikaları (kök dahil) imzanın doğrulama verisinde
     * (CompleteCertificateRefs, CertificateValues, TimeStampValidationData) veya zaman
     * damgasının kendi içinde (CMS SignedData sertifikaları) bulunmalı; yalnız güven
     * deposundaki sertifika referans sayılmaz. TSA iptal verisi kuralıyla aynı kaynaklar:
     * CompleteCertificateRefs imzacı zincirini kapsar (ETSI TS 101 903 §7.4.1), TSA zinciri
     * farklı bir köke bağlanıp doğrulama verisini damganın içinde taşıyabilir.
     * ESXL1_MM_54 / _76: TS C1 → Root C, Root C damganın içinde, geçerli. ESXL1_MM_91: TS C1
     * damgası Root C'yi taşımıyor ve Root C imzada da yok, geçersiz.
     */
    static TrComplianceFinding checkTimestampCertificates(TimestampWrapper timestamp,
                                                          Set<String> validationDataCertificates) {
        Set<String> available = new HashSet<>(validationDataCertificates);
        available.addAll(timestampCertificateIds(timestamp));
        List<CertificateWrapper> chain = timestamp.getCertificateChain();
        String name = tsName(timestamp, timestamp.getSigningCertificate());
        for (int i = 1; chain != null && i < chain.size(); i++) {
            CertificateWrapper certificate = chain.get(i);
            if (available.contains(certificate.getId())) {
                continue;
            }
            boolean root = i == chain.size() - 1 && (certificate.isTrusted() || isSelfIssued(certificate));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("timestampId", timestamp.getId());
            evidence.put("certificateSubject", subjectOf(certificate));
            evidence.put("certificateId", certificate.getId());
            return new TrComplianceFinding(RejectionCode.MDSS_TR_CERT_REF_MISSING,
                    name + " " + (root ? "kök" : "alt kök") + " sertifikası ('" + subjectOf(certificate)
                            + "') ne imzanın doğrulama verisinde (CompleteCertificateRefs / CertificateValues) ne "
                            + "de zaman damgasının içinde var; zaman damgası sertifikası imzanın taşıdığı veriyle "
                            + "doğrulanamıyor. Eksik bilginin tamamlanması gerekmektedir.",
                    Indication.INDETERMINATE, SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE, evidence);
        }
        return null;
    }

    /** Zaman damgasının kendi içinde (CMS SignedData) taşıdığı sertifikalar. */
    private static Set<String> timestampCertificateIds(TimestampWrapper timestamp) {
        Set<String> ids = new HashSet<>();
        if (timestamp.foundCertificates() == null) {
            return ids;
        }
        for (RelatedCertificateWrapper related : timestamp.foundCertificates()
                .getRelatedCertificatesByOrigin(CertificateOrigin.SIGNED_DATA)) {
            ids.add(related.getId());
        }
        return ids;
    }

    /**
     * İmzanın doğrulama verisindeki sertifikalar: CompleteCertificateRefs (özeti eşleşen),
     * CertificateValues ve zaman damgası doğrulama verisi alanları.
     */
    private static Set<String> validationDataCertificateIds(SignatureWrapper signature) {
        Set<String> ids = new HashSet<>();
        for (CertificateOrigin origin : VALIDATION_DATA_CERTIFICATE_ORIGINS) {
            for (RelatedCertificateWrapper related : signature.foundCertificates().getRelatedCertificatesByOrigin(origin)) {
                ids.add(related.getId());
            }
        }
        for (Map.Entry<String, List<RefMatch>> entry : refMatches(signature).entrySet()) {
            for (RefMatch match : entry.getValue()) {
                if (!match.digestPresent || match.digestMatch) {
                    ids.add(entry.getKey());
                }
            }
        }
        return ids;
    }

    /** İmza, doğrulama verisi ve içerik zaman damgalarının TSA iptal verisi imzada bulunmalı; arşiv damgası hariç. */
    static boolean requiresReferencedRevocation(TimestampType type) {
        return type != null && (type.isSignatureTimestamp() || type.isValidationDataTimestamp()
                || type.isContentTimestamp());
    }

    // ---------------------------------------------------------------------------------
    // DSS diagnostic → model
    // ---------------------------------------------------------------------------------

    /**
     * Esnek modda imzacı zinciri için kullanılabilir iptal verisi: imzanın kendi taşıdığı veri
     * ve DSS'in çevrimiçi / önbellekten bulduğu veri. Yalnız zaman damgasının içinde (CMS)
     * gelen veri TSA zinciri içindir; imzacı zincirinin iptal durumunu kanıtlamaz.
     */
    static Set<String> signerChainIds(SignatureWrapper signature) {
        Set<String> ids = new HashSet<>();
        if (signature.foundRevocations() != null) {
            for (RelatedRevocationWrapper revocation : signature.foundRevocations().getRelatedRevocationData()) {
                ids.add(revocation.getId());
            }
        }
        List<CertificateWrapper> chain = signature.getCertificateChain();
        if (chain != null) {
            for (CertificateWrapper certificate : chain) {
                for (CertificateRevocationWrapper revocation : certificate.getCertificateRevocationData()) {
                    if (!revocation.isInternalRevocationOrigin()) {
                        ids.add(revocation.getId());
                    }
                }
            }
        }
        return ids;
    }

    static Set<String> referencedRevocationIds(SignatureWrapper signature) {
        Set<String> ids = new HashSet<>();
        if (signature == null || signature.foundRevocations() == null) {
            return ids;
        }
        for (RelatedRevocationWrapper revocation : signature.foundRevocations().getRelatedRevocationData()) {
            for (RevocationOrigin origin : revocation.getOrigins()) {
                if (REFERENCED_ORIGINS.contains(origin)) {
                    ids.add(revocation.getId());
                }
            }
        }
        return ids;
    }

    /** İmza RevocationValues (veya eşdeğeri) alanında iptal verisi taşıyor mu: -XL / -A. */
    static boolean hasReferencedRevocationData(SignatureWrapper signature) {
        return signature != null
                && (!referencedRevocationIds(signature).isEmpty() || hasReferencedOrphans(signature));
    }

    private static boolean hasReferencedOrphans(SignatureWrapper signature) {
        if (signature.foundRevocations() == null) {
            return false;
        }
        for (OrphanRevocationWrapper orphan : signature.foundRevocations().getOrphanRevocationData()) {
            for (RevocationOrigin origin : orphan.getOrigins()) {
                if (REFERENCED_ORIGINS.contains(origin)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean hasCertificateValues(SignatureWrapper signature) {
        return signature.foundCertificates() != null
                && (!signature.foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).isEmpty()
                || !signature.foundCertificates().getOrphanCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES).isEmpty());
    }

    private static Set<String> certificateValueIds(SignatureWrapper signature) {
        Set<String> ids = new HashSet<>();
        for (RelatedCertificateWrapper related : signature.foundCertificates()
                .getRelatedCertificatesByOrigin(CertificateOrigin.CERTIFICATE_VALUES)) {
            ids.add(related.getId());
        }
        return ids;
    }

    static RevocationRefs revocationRefs(SignatureWrapper signature) {
        RevocationRefs refs = new RevocationRefs();
        if (signature.foundRevocations() == null) {
            return refs;
        }
        for (RelatedRevocationWrapper revocation : signature.foundRevocations().getRelatedRevocationData()) {
            boolean value = revocation.getOrigins().contains(RevocationOrigin.REVOCATION_VALUES);
            boolean referenced = false;
            for (RevocationRefWrapper ref : revocation.getReferences()) {
                if (ref.getOrigins().contains(RevocationRefOrigin.COMPLETE_REVOCATION_REFS)) {
                    referenced = true;
                    refs.present = true;
                }
            }
            if (value && !referenced) {
                refs.unreferencedValues.add(describe(revocation));
            } else if (!value && referenced) {
                // Referans RevocationValues dışındaki bir veriyle (ör. zaman damgası içindeki
                // SİL) eşleşiyor: imzanın kendi değeri yok veya değiştirilmiş.
                refs.valuelessReferences.add(describe(revocation));
            }
        }
        for (OrphanRevocationWrapper orphan : signature.foundRevocations().getOrphanRevocationData()) {
            // DSS'in sertifikaya bağlayamadığı (ör. imzası bozuk) ama RevocationValues içinde
            // bulunan değer referansıyla eşleşiyor; sorunu iptal verisi kuralı raporlar.
            // Yalnız referanstan bilinen (değeri olmayan) token eşleşmeyen referanstır.
            boolean value = orphan.getOrigins().contains(RevocationOrigin.REVOCATION_VALUES);
            for (RevocationRefWrapper ref : orphan.getReferences()) {
                if (ref.getOrigins().contains(RevocationRefOrigin.COMPLETE_REVOCATION_REFS)) {
                    refs.present = true;
                    if (!value) {
                        refs.valuelessReferences.add(orphan.getRevocationType() == RevocationType.CRL
                                ? "SİL" : "OCSP cevabı");
                    }
                }
            }
        }
        return refs;
    }

    private static String describe(RevocationWrapper revocation) {
        CertificateWrapper issuer = revocation.getSigningCertificate();
        return (revocation.getRevocationType() == RevocationType.CRL ? "SİL" : "OCSP cevabı")
                + " ('" + (issuer != null ? issuer.getCommonName() : "düzenleyici bilinmiyor") + "', "
                + TrComplianceChecker.display(revocation.getThisUpdate()) + ")";
    }

    private static boolean hasCompleteCertificateRefs(SignatureWrapper signature) {
        return signature.foundCertificates() != null
                && (!signature.foundCertificates().getRelatedCertificateRefsByRefOrigin(
                        CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).isEmpty()
                || !signature.foundCertificates().getOrphanCertificateRefsByRefOrigin(
                        CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).isEmpty());
    }

    private static Map<String, List<RefMatch>> refMatches(SignatureWrapper signature) {
        Map<String, List<RefMatch>> matches = new LinkedHashMap<>();
        for (RelatedCertificateWrapper related : signature.foundCertificates()
                .getRelatedCertificatesByRefOrigin(CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS)) {
            List<RefMatch> list = new ArrayList<>();
            for (CertificateRefWrapper ref : related.getReferences()) {
                if (ref.getOrigin() == CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS) {
                    list.add(new RefMatch(ref.isDigestValuePresent(), ref.isDigestValueMatch()));
                }
            }
            matches.put(related.getId(), list);
        }
        return matches;
    }

    private static List<CertNode> nodes(List<CertificateWrapper> chain, Set<String> referencedIds) {
        List<CertNode> nodes = new ArrayList<>();
        if (chain != null) {
            for (CertificateWrapper certificate : chain) {
                nodes.add(certNode(certificate, referencedIds, 0));
            }
        }
        return nodes;
    }

    /**
     * @param referencedIds imzanın referans verdiği iptal verisi kimlikleri; {@code null} ise
     *                      sertifikanın tüm iptal verisi referans verilmiş sayılır
     */
    static CertNode certNode(CertificateWrapper certificate, Set<String> referencedIds, int depth) {
        CertNode node = new CertNode(certificate.getId(), subjectOf(certificate), certificate.getNotBefore(),
                certificate.getNotAfter(), certificate.isTrusted(), isSelfIssued(certificate),
                certificate.isSignatureIntact(), certificate.isIdPkixOcspNoCheck());
        List<CertificateRevocationWrapper> revocations = certificate.getCertificateRevocationData();
        if (revocations == null) {
            return node;
        }
        for (CertificateRevocationWrapper revocation : revocations) {
            CertNode responder = null;
            CertificateWrapper signer = revocation.getSigningCertificate();
            if (revocation.getRevocationType() == RevocationType.OCSP && signer != null && depth < MAX_RESPONDER_DEPTH
                    && !signer.getId().equals(certificate.getId())) {
                responder = certNode(signer, referencedIds, depth + 1);
            }
            node.revocations.add(new RevNode(revocation.getId(), revocation.getRevocationType(),
                    referencedIds == null || referencedIds.contains(revocation.getId()),
                    revocation.getProductionDate(), revocation.getThisUpdate(), revocation.getNextUpdate(),
                    revocation.isSignatureIntact(), revocation.getStatus(), revocation.getRevocationDate(),
                    responder));
        }
        return node;
    }

    private static boolean isSelfIssued(CertificateWrapper certificate) {
        String subject = certificate.getCertificateDN();
        return subject != null && subject.equals(certificate.getCertificateIssuerDN());
    }

    private static String subjectOf(CertificateWrapper certificate) {
        return certificate.getCertificateDN() != null ? certificate.getCertificateDN() : certificate.getCommonName();
    }

    private static String tsName(TimestampWrapper timestamp, CertificateWrapper tsa) {
        String kind = timestamp.getType() != null && timestamp.getType().isSignatureTimestamp()
                ? "İmza zaman damgasının" : timestamp.getType() != null && timestamp.getType().isArchivalTimestamp()
                ? "Arşiv zaman damgasının" : "Zaman damgasının";
        return tsa != null && tsa.getCommonName() != null ? kind + " (" + tsa.getCommonName() + ")" : kind;
    }

    private static List<String> otherSources(CertNode certificate) {
        List<String> sources = new ArrayList<>();
        for (RevNode revocation : certificate.revocations) {
            sources.add(revocation.label() + " " + TrComplianceChecker.iso(revocation.thisUpdate));
        }
        return sources;
    }

    private static List<X509CRL> parseCrls(Collection<byte[]> binaries) {
        List<X509CRL> crls = new ArrayList<>();
        if (binaries == null) {
            return crls;
        }
        for (byte[] binary : binaries) {
            try {
                crls.add((X509CRL) CertificateFactory.getInstance("X.509")
                        .generateCRL(new ByteArrayInputStream(binary)));
            } catch (Exception e) {
                // Okunamayan SİL DSS tarafından da bağlanamaz; kural bunu "veri yok" olarak raporlar.
            }
        }
        return crls;
    }

    private static List<X509CRL> orphanCrlsOf(X509Certificate issuer, List<X509CRL> crls) {
        List<X509CRL> result = new ArrayList<>();
        if (issuer == null) {
            return result;
        }
        for (X509CRL crl : crls) {
            if (crl.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                result.add(crl);
            }
        }
        return result;
    }

    /** Düzenleyicinin DN'ini taşıyan ama açık anahtarıyla doğrulanamayan ilk SİL. */
    private static X509CRL firstUnverifiableCrl(List<X509CRL> crls, X509Certificate issuer) {
        if (issuer == null || crls == null) {
            return null;
        }
        X509CRL unverifiable = null;
        for (X509CRL crl : crls) {
            try {
                crl.verify(issuer.getPublicKey(), BC);
                return null;
            } catch (Exception e) {
                if (unverifiable == null) {
                    unverifiable = crl;
                }
            }
        }
        return unverifiable;
    }

    private static X509Certificate x509(CertificateWrapper wrapper) {
        byte[] binaries = wrapper.getBinaries();
        if (binaries == null || binaries.length == 0) {
            return null;
        }
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(binaries));
        } catch (Exception e) {
            return null;
        }
    }

    private static List<LaterRevocation> dedupe(List<LaterRevocation> revocations) {
        Map<String, LaterRevocation> unique = new LinkedHashMap<>();
        for (LaterRevocation revocation : revocations) {
            unique.putIfAbsent(revocation.getSubject() + "|" + revocation.getRevocationDate(), revocation);
        }
        return new ArrayList<>(unique.values());
    }

    private static void add(List<TrComplianceFinding> findings, TrComplianceFinding finding) {
        if (finding != null) {
            findings.add(finding);
        }
    }

}
