# MDSS-TR-CERT-REF-INVALID

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-CERT-REF-INVALID` |
| Başlık | Sertifika referans bilgisi hatalı |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) — sıkı referans |
| İlgili enum | [`RejectionCode.MDSS_TR_CERT_REF_INVALID`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#checkCertificateRefs` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` ve `verification.tr-compliance.strict-reference-enabled` / `TR_STRICT_REFERENCE_ENABLED` (ikisi de default `true`) |
| DSS PASSED iken verdict | `INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE` |
| Örnek paket | `ESXL1_MM_58` (kök), `ESXL1_MM_60` (alt kök) |

## Sorunun özeti

`CompleteCertificateRefs` içindeki referans düzenleyici/seri numarasıyla zincirdeki CA sertifikasını gösteriyor, ancak özet değeri sertifikayla eşleşmiyor.

## Neden DSS yakalamıyor

DSS eşleşmeyen özeti diagnostic veride (`digestValueMatch=false`) raporlar ama politikada buna karşılık gelen bir kural yoktur.

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
  "certificateSubject": "C=TR,O=Valid,CN=SubRoot A1",
  "certificateId": "C-A8FD…"
}
```

## Giderme

Referansın özeti doğru sertifikadan yeniden hesaplanmalı.

## İlgili

- Tüm kodlar: [README](./README.md)
