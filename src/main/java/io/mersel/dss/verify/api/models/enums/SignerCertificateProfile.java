package io.mersel.dss.verify.api.models.enums;

/**
 * İmzacı sertifikasının Türkiye ekosistemindeki profilini (türünü) belirler.
 *
 * <p>Doğrulama politikasının operatör tarafından "mali mühür mü, e-imza mı"
 * diye seçilmesi yerine sertifikanın kendisindeki OID kanıtlarından profil
 * tespit edilir; profile özgü kurallar (ör. KeyUsage zorunlulukları) bu
 * tesbite göre uygulanır. TÜBİTAK doğrulayıcısı da mali mühür ve
 * NES/e-imza sertifikalarını farklı kurallarla denetler.</p>
 *
 * <p>Tespit sinyalleri (değerlendirme sırasıyla):</p>
 * <ol>
 *   <li>Mali mühür politika OID'i veya mali mühür EKU OID'i — mühür kanıtı
 *       NES politikasının önündedir (NES politikasını yanlışlıkla taşıyan
 *       mühür sertifikası NES sayılmaz). EKU her mühür sertifikasında
 *       bulunmayabilir.</li>
 *   <li>NES politika OID'i.</li>
 *   <li>QC statement OID'leri — destekleyici kanıt.</li>
 * </ol>
 *
 * @see io.mersel.dss.verify.api.services.util.SignerCertificateProfileDetector
 */
public enum SignerCertificateProfile {

    /** Nitelikli elektronik imza sertifikası (kişisel, QC A* ailesi). */
    NES_E_IMZA("Nitelikli elektronik imza (e-imza/NES)"),

    /** Mali mühür sertifikası (kurumsal, MM A* ailesi). */
    MALI_MUHUR("Mali mühür"),

    /** Profil OID kanıtlarından belirlenemedi; profile özgü kural uygulanmaz. */
    UNKNOWN("Profil belirlenemedi");

    private final String label;

    SignerCertificateProfile(String label) {
        this.label = label;
    }

    /** İnsan-okunaklı etiket (raporlarda ve loglarda kullanılır). */
    public String getLabel() {
        return label;
    }
}
