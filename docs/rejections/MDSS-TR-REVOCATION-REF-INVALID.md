# MDSS-TR-REVOCATION-REF-INVALID

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-REVOCATION-REF-INVALID` |
| Başlık | İptal referans bilgisi hatalı |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) — sıkı referans |
| İlgili enum | [`RejectionCode.MDSS_TR_REVOCATION_REF_INVALID`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#checkRevocationRefs` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` ve `verification.tr-compliance.strict-reference-enabled` / `TR_STRICT_REFERENCE_ENABLED` (ikisi de default `true`) |
| DSS PASSED iken verdict | `INDETERMINATE / TRY_LATER` |
| Örnek paket | `ESXL1_MM_62`, `_64`, `_66`, `_68` (hatalı referans özeti), `_88`, `_90` (değiştirilmiş OCSP değeri) |

## Sorunun özeti

`RevocationValues` içinde referansı olmayan bir değer **ve** değeri olmayan bir referans birlikte var: referansın özeti yanlış hesaplanmış ya da iptal değeri sonradan değiştirilmiş. Yalnız referansı olmayan değer [`MDSS-TR-REVOCATION-REF-MISSING`](./MDSS-TR-REVOCATION-REF-MISSING.md), yalnız değeri olmayan referans [`MDSS-TR-REVOCATION-DATA-MISSING`](./MDSS-TR-REVOCATION-DATA-MISSING.md) ile raporlanır.

## Neden DSS yakalamıyor

DSS eşleşmeyen referansı diagnostic veride (yetim referans) raporlar ama politikada buna karşılık gelen bir kural yoktur; değiştirilmiş değer yerine çevrimiçi veriyi kullanabilir.

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
  "unreferencedValues": ["OCSP cevabı ('OCSP A1', 05.01.2023 12:01:20)"],
  "unmatchedReferences": ["OCSP"]
}
```

## Giderme

Referans, imzadaki iptal değerinden yeniden hesaplanmalı veya değiştirilmiş değer özgün haliyle değiştirilmeli.

## İlgili

- Tüm kodlar: [README](./README.md)
