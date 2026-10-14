# MDSS-TR-REVOCATION-DATA-MISSING

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-REVOCATION-DATA-MISSING` |
| Başlık | İptal bilgisi imzada yok |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) — sıkı referans |
| İlgili enum | [`RejectionCode.MDSS_TR_REVOCATION_DATA_MISSING`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#evaluateRevocation` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` ve `verification.tr-compliance.strict-reference-enabled` / `TR_STRICT_REFERENCE_ENABLED` (ikisi de default `true`) |
| DSS PASSED iken verdict | `INDETERMINATE / TRY_LATER` |
| Örnek paket | `ESXL1_MM_25`, `ESXL1_MM_83`, `_85`, `_86`, `_87`, `_89` (referansı olan değer yok), `ESXL1_MM_92` |

## Sorunun özeti

Uzun dönemli imzada (`RevocationValues` var) bir sertifikanın iptal bilgisi imzada yok:

- imzacı zinciri için `RevocationValues` içinde,
- TSA zinciri için ne `RevocationValues` içinde ne de zaman damgasının kendi içinde.

`CompleteRevocationRefs` içinde referansı olan bir SİL / OCSP cevabının `RevocationValues`
içinde değeri yoksa ("İptal değeri eksik") ve OCSP cevabı sertifika durumunu `unknown`
bildirirse de bu kod kullanılır.
Arayüz "Eksik bilginin tamamlanması gerekmektedir" önerisini gösterir.

## Neden DSS yakalamıyor

DSS eksik veriyi çevrimiçi (SİL dağıtım noktası / OCSP) tamamlar.

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
  "certificateSubject": "…",
  "role": "CA",
  "controlTime": "…",
  "controlTimeSource": "imza zaman damgası",
  "otherRevocationSources": ["SİL 2019-05-30T10:00:00Z"]
}
```

## Giderme

İmzanın `RevocationValues` alanına sertifikanın SİL veya OCSP cevabı eklenmeli.

## İlgili

- Tüm kodlar: [README](./README.md)
