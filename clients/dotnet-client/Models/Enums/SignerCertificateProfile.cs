using System.Text.Json.Serialization;

namespace MERSEL.Services.DssVerifier.Client.Models.Enums;

/// <summary>
/// İmzacı sertifikasının OID kanıtlarından tespit edilen profili.
/// </summary>
/// <remarks>
/// <para>
/// Tespit sırası: mali mühür politika OID'i (<c>2.16.792.1.2.1.1.5.7.4.1</c>) veya
/// mali mühür EKU'su (<c>2.16.792.1.2.1.1.5.7.50.1</c>) → <see cref="MALI_MUHUR"/>;
/// NES politika OID'i (<c>2.16.792.1.2.1.1.5.7.1.1</c>) veya 5070 sayılı Kanun QC
/// ibaresi (<c>2.16.792.1.61.0.1.5070.*</c>) → <see cref="NES_E_IMZA"/>; kanıt yoksa
/// <see cref="UNKNOWN"/>.
/// </para>
/// <para>
/// Bu alan <em>doğrulama kararını</em> etkilemez; yalnız görünürlük içindir.
/// Nitelikli sertifika ibarelerinin kendisi <see cref="CertificateInfo.QcStatements"/>
/// alanındadır.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum SignerCertificateProfile
{
    /// <summary>Nitelikli elektronik imza (e-imza / NES) sertifikası.</summary>
    NES_E_IMZA,

    /// <summary>Mali mühür sertifikası.</summary>
    MALI_MUHUR,

    /// <summary>Sertifikada profili belirleyen OID kanıtı yok.</summary>
    UNKNOWN
}
