package io.mersel.dss.verify.api.models.enums;

/**
 * Mersel DSS Verifier'ın bir imzayı reddederken DSS'in soyut
 * <code>SubIndication</code>'ından öte <strong>Mersel'e özgü, kararlı,
 * makine-okunaklı bir gerekçe kodu</strong> raporladığı durumlar için
 * kod kümesi.
 *
 * <h3>{@link SuppressionCode} ile farkı</h3>
 * <ul>
 *   <li><b>SuppressionCode</b> — DSS verdict'ini <em>override</em>
 *       ediyoruz: DSS INVALID dedi, biz VALID diyoruz. Gerekçe + kanıt
 *       audit için raporlanır.</li>
 *   <li><b>RejectionCode</b> — DSS verdict'ini <em>destekliyoruz</em>:
 *       DSS INVALID dedi, biz de INVALID diyoruz, AMA neden invalid
 *       olduğunu Türkiye ekosistemine spesifik bir tanı koduyla
 *       açıklıyoruz. Operatör DSS'in jenerik
 *       <code>SIG_CONSTRAINTS_FAILURE</code>'ından öte, hangi
 *       Türkiye-pratiği patolojinin tetiklediğini görür.</li>
 *   <li><b>MDSS-TR-*</b> — TR uyum kontrolleri
 *       ({@code verification.tr-compliance.enabled}). MA3 politikasının DSS
 *       şemasıyla ifade edilemeyen kuralları; DSS PASSED dediğinde de imzayı
 *       reddedebilir. DSS'in asıl kararı
 *       {@code AppliedRejection.originalIndication} alanındadır.</li>
 * </ul>
 *
 * <h3>Naming convention</h3>
 * <p><code>MDSS-{LAYER}-{DESCRIPTIVE-SLUG}</code> — aynı şema
 * {@link SuppressionCode} ile paylaşılır. Aynı kod hem suppression hem
 * rejection olarak görünmez; eklerken çakışma kontrol edilmelidir.</p>
 *
 * <h3>Kararlılık (stability) kuralları</h3>
 * <ol>
 *   <li>Yeni değer <em>eklenebilir</em>.</li>
 *   <li>Mevcut değer renaming edilmez; davranış değişiyorsa yeni kod
 *       eklenir, eskisi <code>@Deprecated</code> işaretlenir.</li>
 *   <li>Her kod için <code>title</code>, <code>defaultReason</code>,
 *       <code>severity</code> ve <code>docsUrl</code> sabittir.</li>
 * </ol>
 */
public enum RejectionCode {

    /**
     * XAdES imza yalnızca <strong>bir</strong> <code>&lt;ds:Reference&gt;</code>
     * taşıyor; <code>&lt;xades:SignedProperties&gt;</code> elementi XML
     * içinde mevcut fakat hiçbir Reference ona pointing değil. ETSI EN
     * 319 132-1 (XAdES-BES) iki referans (biri belge body'si, biri
     * SignedProperties) zorunluluğuna aykırı.
     *
     * <h4>Güvenlik etkisi ve yapısal sorun</h4>
     * <ul>
     *   <li>İkinci referans olmadığı için <code>SigningTime</code>,
     *       <code>SigningCertificate</code>, <code>SignaturePolicyIdentifier</code>,
     *       <code>SignerRole</code>, <code>CommitmentTypeIndication</code>
     *       gibi imzanın anlamını taşıyan alanlar <em>imza kapsamı
     *       dışında</em>dır — post-signing modifiye edilebilir ve imza
     *       yine matematik olarak doğrulanır. Doğrulayıcı bu tahrifatı
     *       yakalayamaz.</li>
     *   <li>Bu yapı eIDAS ve 5070 sayılı kanunun atıfta bulunduğu ETSI
     *       standartları açısından geçerli bir advanced electronic
     *       signature değildir.</li>
     *   <li>Çözüm doğrulayıcı tarafında değil, imzayı üreten yazılım
     *       tarafındadır: iki referans (biri body, biri SignedProperties)
     *       üretilmelidir.</li>
     * </ul>
     *
     * @see io.mersel.dss.verify.api.services.verification.AdvancedSignatureVerificationService#evaluateTrLegacyXadesRejection
     */
    MDSS_XADES_LEGACY_TR_MISSING_SP_REFERENCE(
            "MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE",
            "XAdES SignedProperties referansı eksik (tek referanslı imza)",
            "XAdES imza yalnızca bir ds:Reference taşıyor; SignedProperties "
                    + "imza kapsamına alınmamış. SigningTime ve SigningCertificate "
                    + "gibi alanlar kriptografik olarak korunmadığı için "
                    + "post-signing tahrifata açık. ETSI EN 319 132-1 (XAdES-BES) "
                    + "iki referans zorunluluğuna aykırı; imza reddedildi.",
            "ERROR",
            "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/rejections/MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE.md"),

    /**
     * İmzacı sertifikasının profili (mali mühür / e-imza) OID kanıtlarından
     * tespit edilmiş ve sertifika o profilin KeyUsage zorunluluğunu
     * karşılamıyor. TÜBİTAK doğrulayıcısının profil bazlı KeyUsage yorumu:
     * <ul>
     *   <li>e-imza/NES — {@code digitalSignature} <strong>ve</strong>
     *       {@code nonRepudiation} birlikte zorunlu;</li>
     *   <li>mali mühür — yalnız {@code digitalSignature} zorunlu
     *       (mühür sertifikalarında nonRepudiation bulunmaz).</li>
     * </ul>
     * Bu kontrol DSS sonrası gate katmanında çalışır ve DSS PASSED dese bile
     * imzayı reddedebilir; DSS'in asıl kararı
     * {@code AppliedRejection.originalIndication} alanında saklanır.
     *
     * @see io.mersel.dss.verify.api.services.util.SignerCertificateProfileDetector
     */
    MDSS_TR_KEYUSAGE_PROFILE(
            "MDSS-TR-KEYUSAGE-PROFILE",
            "İmzacı sertifikası profilinin KeyUsage gereksinimi karşılanmıyor",
            "Sertifika profili (e-imza/NES veya mali mühür) OID'lerden tespit "
                    + "edildi ve profilin zorunlu KeyUsage bit'leri tamam değil: "
                    + "e-imza sertifikalarında digitalSignature ve nonRepudiation "
                    + "birlikte, mali mühür sertifikalarında digitalSignature "
                    + "zorunludur. İmza reddedildi.",
            "ERROR",
            "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/rejections/MDSS-TR-KEYUSAGE-PROFILE.md"),

    // ------------------------------------------------------------------
    // TR uyum kontrolleri (verification.tr-compliance.enabled).
    //
    // TÜBİTAK e-Fatura ön hazırlık değerlendirmesindeki MA3 doğrulama
    // politikasının DSS politika şemasıyla ifade edilemeyen kuralları.
    // Bu kodlar DSS PASSED dediğinde de imzayı reddedebilir; o durumda
    // AppliedRejection.originalIndication DSS'in asıl kararını taşır.
    // Ayrıntı: docs/rejections/MDSS-TR-*.md
    //
    // NES nonRepudiation (ESXL1_MM_7) burada değil: profil bazlı KeyUsage
    // kuralı MDSS_TR_KEYUSAGE_PROFILE ile bayraktan bağımsız uygulanır.
    // ------------------------------------------------------------------

    /**
     * Üst seviye XAdES imza, imzalanan veriye belge dışından (ayrık) başvuruyor ve
     * özgün belgeyle doğrulanamadı (belge gönderilmedi veya referanslarla eşleşmedi).
     */
    MDSS_TR_XADES_DETACHED(
            "MDSS-TR-XADES-DETACHED",
            "Ayrık imza özgün belgeyle doğrulanamadı",
            "Ayrık (detached) imza, imzalanan veriye belge dışından başvuruyor ve "
                    + "özgün belgeyle doğrulanamadı: özgün belge gönderilmedi ya da "
                    + "imzanın ayrık referanslarıyla eşleşmedi.",
            "ERROR",
            docs("MDSS-TR-XADES-DETACHED")),

    /** Zincirdeki bir sertifikanın imzası, onu düzenleyen sertifikayla doğrulanamıyor. */
    MDSS_TR_CERT_SIGNATURE_INVALID(
            "MDSS-TR-CERT-SIGNATURE-INVALID",
            "Sertifika imzası bozuk",
            "Sertifikanın imzası, onu düzenleyen sertifikanın açık anahtarıyla "
                    + "doğrulanamadı; sertifika imzası bozuk veya sahte.",
            "ERROR",
            docs("MDSS-TR-CERT-SIGNATURE-INVALID")),

    /** İmza zamanında imzacı sertifikasının geçerlilik süresi dolmuş. */
    MDSS_TR_CERT_EXPIRED_AT_SIGNING_TIME(
            "MDSS-TR-CERT-EXPIRED-AT-SIGNING-TIME",
            "Sertifikanın süresi dolmuş",
            "İmza zamanında imzacı sertifikasının geçerlilik süresi dolmuştu.",
            "ERROR",
            docs("MDSS-TR-CERT-EXPIRED-AT-SIGNING-TIME")),

    /** İmza zamanında imzacı sertifikası henüz geçerli değil. */
    MDSS_TR_CERT_NOT_YET_VALID_AT_SIGNING_TIME(
            "MDSS-TR-CERT-NOT-YET-VALID-AT-SIGNING-TIME",
            "Sertifika henüz geçerli değil",
            "İmza zamanında imzacı sertifikasının geçerlilik süresi henüz başlamamıştı.",
            "ERROR",
            docs("MDSS-TR-CERT-NOT-YET-VALID-AT-SIGNING-TIME")),

    /** İptal kontrolünde kullanılabilecek SİL'lerin tümünün geçerlilik süresi kontrol zamanında dolmuş. */
    MDSS_TR_CRL_EXPIRED(
            "MDSS-TR-CRL-EXPIRED",
            "SİL'in geçerlilik süresi dolmuş",
            "Sertifikanın iptal durumu için kullanılan SİL'in geçerlilik süresi "
                    + "(nextUpdate) kontrol zamanından önce dolmuş; güncel iptal bilgisi yok.",
            "ERROR",
            docs("MDSS-TR-CRL-EXPIRED")),

    // Sıkı referans kullanımı (MA3 force-strict-reference-use). Uzun dönemli
    // (-C / -X / -XL / -A) imzada doğrulama, imzanın referans verdiği veriyle
    // (CompleteCertificateRefs, RevocationValues) yapılır; DSS'in çevrimiçi
    // veya zaman damgası içinden bulduğu başka veri bu veriyi ikame etmez.
    // Ayrıntı: docs/rejections/MDSS-TR-*.md

    /** Zincirdeki bir CA sertifikası (kök / alt kök) CompleteCertificateRefs içinde yok. */
    MDSS_TR_CERT_REF_MISSING(
            "MDSS-TR-CERT-REF-MISSING",
            "Sertifika referans bilgisi eksik",
            "İmzanın sertifika referanslarında (CompleteCertificateRefs) zincirdeki "
                    + "bir CA sertifikasının referans bilgisi yok. Eksik bilginin "
                    + "tamamlanması gerekmektedir.",
            "ERROR",
            docs("MDSS-TR-CERT-REF-MISSING")),

    /** CompleteCertificateRefs içindeki bir referans, zincirdeki sertifikayla eşleşmiyor. */
    MDSS_TR_CERT_REF_INVALID(
            "MDSS-TR-CERT-REF-INVALID",
            "Sertifika referans bilgisi hatalı",
            "İmzanın sertifika referanslarındaki (CompleteCertificateRefs) bir "
                    + "referansın özeti, zincirdeki sertifikayla eşleşmiyor.",
            "ERROR",
            docs("MDSS-TR-CERT-REF-INVALID")),

    /** Zincirdeki bir CA sertifikası (kök / alt kök) imzanın CertificateValues alanında yok. */
    MDSS_TR_CERT_VALUE_MISSING(
            "MDSS-TR-CERT-VALUE-MISSING",
            "Sertifika değeri eksik",
            "İmzanın sertifika değerlerinde (CertificateValues) zincirdeki bir CA "
                    + "sertifikası yok; sıkı referans kullanımında güven deposu veya AIA ile "
                    + "bulunan sertifika kullanılmaz. Eksik bilginin tamamlanması gerekmektedir.",
            "ERROR",
            docs("MDSS-TR-CERT-VALUE-MISSING")),

    /** RevocationValues içindeki bir SİL / OCSP cevabının CompleteRevocationRefs içinde referansı yok. */
    MDSS_TR_REVOCATION_REF_MISSING(
            "MDSS-TR-REVOCATION-REF-MISSING",
            "İptal referans bilgisi eksik",
            "İmzanın iptal değerlerindeki (RevocationValues) bir SİL / OCSP cevabının iptal "
                    + "referanslarında (CompleteRevocationRefs) referans bilgisi yok. Eksik bilginin "
                    + "tamamlanması gerekmektedir.",
            "ERROR",
            docs("MDSS-TR-REVOCATION-REF-MISSING")),

    /** RevocationValues ile CompleteRevocationRefs birbiriyle eşleşmiyor. */
    MDSS_TR_REVOCATION_REF_INVALID(
            "MDSS-TR-REVOCATION-REF-INVALID",
            "İptal referans bilgisi hatalı",
            "İmzanın iptal değerlerindeki (RevocationValues) bir SİL / OCSP cevabı, iptal "
                    + "referanslarındaki (CompleteRevocationRefs) özetle eşleşmiyor.",
            "ERROR",
            docs("MDSS-TR-REVOCATION-REF-INVALID")),

    /** Sertifikanın iptal bilgisi imzanın RevocationValues alanında yok. */
    MDSS_TR_REVOCATION_DATA_MISSING(
            "MDSS-TR-REVOCATION-DATA-MISSING",
            "İptal bilgisi imzada yok",
            "Sertifikanın iptal bilgisi (SİL / OCSP) imzanın RevocationValues "
                    + "alanında yok; sıkı referans kullanımında çevrimiçi veya zaman "
                    + "damgası içindeki veri kullanılmaz. Eksik bilginin tamamlanması "
                    + "gerekmektedir.",
            "ERROR",
            docs("MDSS-TR-REVOCATION-DATA-MISSING")),

    /** İmzadaki SİL veya OCSP cevabının imzası, düzenleyicisiyle doğrulanamıyor. */
    MDSS_TR_REVOCATION_SIGNATURE_INVALID(
            "MDSS-TR-REVOCATION-SIGNATURE-INVALID",
            "İptal bilgisinin imzası bozuk",
            "İmzadaki SİL veya OCSP cevabının imzası, onu düzenleyen sertifikayla "
                    + "doğrulanamadı.",
            "ERROR",
            docs("MDSS-TR-REVOCATION-SIGNATURE-INVALID")),

    /** İmzadaki OCSP cevabı kontrol zamanındaki iptal durumunu kanıtlamıyor. */
    MDSS_TR_OCSP_EXPIRED(
            "MDSS-TR-OCSP-EXPIRED",
            "OCSP cevabının süresi dolmuş",
            "İmzadaki OCSP cevabı kontrol zamanından önce üretilmiş veya geçerlilik "
                    + "süresi (nextUpdate) dolmuş; kontrol zamanındaki iptal durumunu "
                    + "kanıtlamıyor.",
            "ERROR",
            docs("MDSS-TR-OCSP-EXPIRED")),

    /** OCSP cevabını imzalayan sertifika süresi dolmuş, imzası bozuk veya iptal edilmiş. */
    MDSS_TR_OCSP_RESPONDER_INVALID(
            "MDSS-TR-OCSP-RESPONDER-INVALID",
            "OCSP sertifikası geçersiz",
            "OCSP cevabını imzalayan sertifika, cevabın üretildiği anda geçerli değil "
                    + "(süresi dolmuş, imzası bozuk veya iptal edilmiş).",
            "ERROR",
            docs("MDSS-TR-OCSP-RESPONDER-INVALID")),

    /** Zincirdeki bir sertifika kontrol zamanından önce iptal edilmiş. */
    MDSS_TR_CERT_REVOKED(
            "MDSS-TR-CERT-REVOKED",
            "Sertifika iptal edilmiş",
            "Zincirdeki bir sertifika (alt kök, zaman damgası veya imzacı), imzadaki "
                    + "iptal bilgisine göre kontrol zamanından önce iptal edilmiş.",
            "ERROR",
            docs("MDSS-TR-CERT-REVOKED")),

    /** Güven kökü olarak eklenmiş kendinden imzalı sertifikanın imzası bozuk. */
    MDSS_TR_TRUST_ANCHOR_SIGNATURE_INVALID(
            "MDSS-TR-TRUST-ANCHOR-SIGNATURE-INVALID",
            "Kök sertifikasının imzası bozuk",
            "Zincirin bağlandığı kök sertifikası kendinden imzalı, ancak imzası kendi "
                    + "açık anahtarıyla doğrulanamadı.",
            "ERROR",
            docs("MDSS-TR-TRUST-ANCHOR-SIGNATURE-INVALID")),

    /** İmzanın bir zaman damgasının imzası veya mesaj özeti bozuk. */
    MDSS_TR_TIMESTAMP_INVALID(
            "MDSS-TR-TIMESTAMP-INVALID",
            "Zaman damgası bozuk",
            "İmzanın zaman damgalarından birinin imzası doğrulanamadı veya mesaj "
                    + "özeti damgalanan veriyle eşleşmiyor.",
            "ERROR",
            docs("MDSS-TR-TIMESTAMP-INVALID")),

    /** Zaman damgası sertifikası damga anında geçersiz veya güven köküne bağlanamıyor. */
    MDSS_TR_TSA_CERT_INVALID(
            "MDSS-TR-TSA-CERT-INVALID",
            "Zaman damgası sertifikası geçersiz",
            "Zaman damgası sertifikası damga anında geçerli değil, imzası bozuk veya "
                    + "güvenilir köke bağlanamıyor.",
            "ERROR",
            docs("MDSS-TR-TSA-CERT-INVALID")),


    /** NES: sertifika politikalarında kullanıcı bildirimi (UserNotice) yok. */
    MDSS_TR_NES_CERTIFICATE_POLICY(
            "MDSS-TR-NES-CERTIFICATE-POLICY",
            "NES sertifika politikaları kontrolü başarısız",
            "Nitelikli elektronik sertifikanın sertifika politikalarında "
                    + "kullanıcı bildirimi (UserNotice, 1.3.6.1.5.5.7.2.2) yok.",
            "ERROR",
            docs("MDSS-TR-NES-CERTIFICATE-POLICY")),

    /** NES: nitelikli sertifika ibarelerinde ETSI OID'si (0.4.0.1862.1.1) yok. */
    MDSS_TR_NES_QC_ETSI(
            "MDSS-TR-NES-QC-ETSI",
            "NES nitelikli sertifika ibaresi (ETSI) eksik",
            "Nitelikli sertifika ibarelerinde (QCStatements) ETSI nitelikli "
                    + "sertifika OID'si 0.4.0.1862.1.1 yok.",
            "ERROR",
            docs("MDSS-TR-NES-QC-ETSI")),

    /** NES: nitelikli sertifika ibarelerinde BTK OID'si (2.16.792.1.61.0.1.5070.1.1) yok. */
    MDSS_TR_NES_QC_BTK(
            "MDSS-TR-NES-QC-BTK",
            "NES nitelikli sertifika ibaresi (BTK) eksik",
            "Nitelikli sertifika ibarelerinde (QCStatements) BTK nitelikli "
                    + "sertifika OID'si 2.16.792.1.61.0.1.5070.1.1 yok.",
            "ERROR",
            docs("MDSS-TR-NES-QC-BTK")),

    /** Mali mühür: genişletilmiş anahtar kullanımında 2.16.792.1.2.1.1.5.7.50.1 yok. */
    MDSS_TR_SEAL_EXTENDED_KEY_USAGE(
            "MDSS-TR-SEAL-EXTENDED-KEY-USAGE",
            "Mali mühür anahtar kullanımı kontrolü başarısız",
            "Mali mühür sertifikasının genişletilmiş anahtar kullanımında "
                    + "(EKU) 2.16.792.1.2.1.1.5.7.50.1 yok.",
            "ERROR",
            docs("MDSS-TR-SEAL-EXTENDED-KEY-USAGE")),

    /** Mali mühür: sertifika politikası 2.16.792.1.2.1.1.5.7.4.1 yok. */
    MDSS_TR_SEAL_CERTIFICATE_POLICY(
            "MDSS-TR-SEAL-CERTIFICATE-POLICY",
            "Mali mühür sertifika politikası kontrolü başarısız",
            "Mali mühür sertifikası 2.16.792.1.2.1.1.5.7.4.1 sertifika "
                    + "politikasını taşımıyor.",
            "ERROR",
            docs("MDSS-TR-SEAL-CERTIFICATE-POLICY"));

    private static String docs(String code) {
        return "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/rejections/"
                + code + ".md";
    }

    private final String code;
    private final String title;
    private final String defaultReason;
    private final String severity;
    private final String docsUrl;

    RejectionCode(String code, String title, String defaultReason,
                  String severity, String docsUrl) {
        this.code = code;
        this.title = title;
        this.defaultReason = defaultReason;
        this.severity = severity;
        this.docsUrl = docsUrl;
    }

    /** API'de görünen kararlı string kod (örn. <code>MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE</code>). */
    public String getCode() {
        return code;
    }

    public String getTitle() {
        return title;
    }

    public String getDefaultReason() {
        return defaultReason;
    }

    public String getSeverity() {
        return severity;
    }

    public String getDocsUrl() {
        return docsUrl;
    }
}
