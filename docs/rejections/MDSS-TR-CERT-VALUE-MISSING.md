# MDSS-TR-CERT-VALUE-MISSING

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-CERT-VALUE-MISSING` |
| Başlık | Sertifika değeri eksik |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) — sıkı referans |
| İlgili enum | [`RejectionCode.MDSS_TR_CERT_VALUE_MISSING`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#checkCertificateValues` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` ve `verification.tr-compliance.strict-reference-enabled` / `TR_STRICT_REFERENCE_ENABLED` (ikisi de default `true`) |
| DSS PASSED iken verdict | `INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE` |
| Örnek paket | `ESXL1_MM_79` (kök), `ESXL1_MM_81` (alt kök) |

## Sorunun özeti

İmza `CertificateValues` taşıyor (-XL / -A), ancak imzacı zincirindeki bir CA sertifikası (alt kök veya kök) bu alanda yok. Arayüz gerekçenin yanında "Eksik bilginin tamamlanması gerekmektedir" önerisini gösterir.

## Neden DSS yakalamıyor

DSS eksik sertifikayı güven deposundan (kök) veya AIA ile (alt kök) bulur ve imzayı geçirir.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Sıkı referans kullanımı

TÜBİTAK ön hazırlık kılavuzu MA3 kullanıcılarından `xmlsignature-config.xml`
içinde `force-strict-reference-use=true` ister: uzun dönemli imzada (-C / -X /
-XL / -A) sertifika doğrulaması imzanın **referans verdiği** veriyle
(`CompleteCertificateRefs`, `CertificateValues`, `RevocationValues`) yapılır.
DSS ise bir sertifika için bulduğu en iyi veriyi seçer: imzadaki veri bozuk,
süresi dolmuş veya eksikse zaman damgası içindeki SİL'i ya da çevrimiçi yeni
bir cevabı kullanır ve imzayı geçirir. Bu kod imzanın kendi verisini
değerlendirir; başka bir kaynaktaki geçerli veri onu ikame etmez.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "C=TR,O=Valid,CN=Root A",
  "certificateId": "C-79BD…"
}
```

## Giderme

Eksik CA sertifikası imzanın `CertificateValues` alanına eklenmeli.

## İlgili

- Tüm kodlar: [README](./README.md)
