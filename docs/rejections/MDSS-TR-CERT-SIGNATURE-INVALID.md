# MDSS-TR-CERT-SIGNATURE-INVALID

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-CERT-SIGNATURE-INVALID` |
| Başlık | Sertifika imzası bozuk |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_CERT_SIGNATURE_INVALID`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`TrComplianceChecker#checkIssuerSignature`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/TrComplianceChecker.java) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / CERTIFICATE_CHAIN_GENERAL_FAILURE` |
| Örnek paket | `ESXL1_MM_13` |

## Sorunun özeti

Zincirin koptuğu sertifikanın imzası, aynı DN'li aday düzenleyicilerin (güven kökleri, belgedeki sertifikalar, gerekirse AIA) hiçbirinin açık anahtarıyla doğrulanamıyor.

## Neden DSS yakalamıyor

DSS düzenleyiciyi imza doğrulamasıyla bağlayamadığında zinciri kuramaz ve yalnız "zincir güven kökü içermiyor" (`BBB_XCV_CCCBB`) der.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "…",
  "issuerSubject": "…",
  "candidateIssuerSha256": [
    "…"
  ]
}
```

## Giderme

Sertifika bozuk veya sahtedir; imza geçerli bir sertifikayla yeniden atılmalıdır.

## İlgili

- Tüm kodlar: [README](./README.md)
- NES nonRepudiation kuralı bu bayrağa bağlı değildir:
  [`MDSS-TR-KEYUSAGE-PROFILE`](./MDSS-TR-KEYUSAGE-PROFILE.md)
