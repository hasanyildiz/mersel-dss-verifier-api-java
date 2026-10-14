# MDSS-TR-TSA-CERT-INVALID

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-TSA-CERT-INVALID` |
| Başlık | Zaman damgası sertifikası geçersiz |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_TSA_CERT_INVALID`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#checkTimestamp` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / SIG_CONSTRAINTS_FAILURE` |
| Örnek paket | `ESXL1_MM_49` (süresi dolmuş), `ESXL1_MM_50` (imzası bozuk), `ESXL1_MM_71`, `ESXL1_MM_72` |

## Sorunun özeti

Zaman damgası sertifikası (TSA):

- damganın üretildiği anda geçerli değil (süresi dolmuş / başlamamış),
- veya TSA zincirindeki bir sertifikanın imzası düzenleyicisiyle doğrulanamıyor,
- veya zincir güvenilir köke bağlanamıyor.

Her imza seviyesinde uygulanır.

## Neden DSS yakalamıyor

DSS zaman damgasını INDETERMINATE raporlar ama imzacı sertifikası doğrulama anında geçerliyse imzayı geçirir.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "timestampId": "T-…",
  "tsaSubject": "C=TR,O=Expired,CN=TS A3",
  "tsaNotAfter": "2019-05-30T12:33:42Z",
  "productionTime": "2023-01-05T09:03:39Z"
}
```

## Giderme

Geçerli bir zaman damgası sertifikasıyla yeni zaman damgası alınmalı.

## İlgili

- Tüm kodlar: [README](./README.md)
