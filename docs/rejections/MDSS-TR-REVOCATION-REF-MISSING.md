# MDSS-TR-REVOCATION-REF-MISSING

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-REVOCATION-REF-MISSING` |
| Başlık | İptal referans bilgisi eksik |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) — sıkı referans |
| İlgili enum | [`RejectionCode.MDSS_TR_REVOCATION_REF_MISSING`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#checkRevocationRefs` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` ve `verification.tr-compliance.strict-reference-enabled` / `TR_STRICT_REFERENCE_ENABLED` (ikisi de default `true`) |
| DSS PASSED iken verdict | `INDETERMINATE / TRY_LATER` |
| Örnek paket | `ESXL1_MM_61`, `_63` (SİL), `_65`, `_67` (OCSP), `_84` |

## Sorunun özeti

İmza `CompleteRevocationRefs` taşıyor, ancak `RevocationValues` içindeki bir SİL veya OCSP cevabı için referans yok. Arayüz "Eksik bilginin tamamlanması gerekmektedir" önerisini gösterir.

## Neden DSS yakalamıyor

DSS referanssız değeri yine kullanır; referans kapsamını denetleyen bir politika kuralı yoktur.

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
  "unreferencedValues": ["SİL ('Root A', 30.05.2019 13:00:00)"],
  "unmatchedReferences": []
}
```

## Giderme

Eksik referans `CompleteRevocationRefs` alanına eklenmeli (imza -C/-XL seviyesine yeniden yükseltilmeli).

## İlgili

- Tüm kodlar: [README](./README.md)
