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
