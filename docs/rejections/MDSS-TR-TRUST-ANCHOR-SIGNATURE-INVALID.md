# MDSS-TR-TRUST-ANCHOR-SIGNATURE-INVALID

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-TRUST-ANCHOR-SIGNATURE-INVALID` |
| Başlık | Kök sertifikasının imzası bozuk |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_TRUST_ANCHOR_SIGNATURE_INVALID`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#checkTrustAnchor` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE` |
| Örnek paket | `ESXL1_MM_36` (imzacı zinciri), `ESXL1_MM_53` / `_75` (zaman damgası zinciri), `BES_36`, `EST_36` |

## Sorunun özeti

İmzacı veya zaman damgası zincirinin bağlandığı kendinden imzalı kök sertifikasının imzası kendi açık anahtarıyla doğrulanamıyor. Kök güven deposunda olsa da (ör. test paketindeki `RootB.crt`) bozuk imzalı kök kabul edilmez. Her imza seviyesinde uygulanır; sıkı referans bayrağına bağlı değildir.

## Neden DSS yakalamıyor

DSS güven deposundaki sertifikayı güven çapası kabul eder ve kendi imzasını denetlemez.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "C=TR,O=Signature Forged,CN=Root B",
  "trusted": true
}
```

## Giderme

Kök sertifikası güven deposundan çıkarılmalı veya doğru kök sertifikasıyla değiştirilmeli.

## İlgili

- Tüm kodlar: [README](./README.md)
