# MDSS-TR-TIMESTAMP-INVALID

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-TIMESTAMP-INVALID` |
| Başlık | Zaman damgası bozuk |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_TIMESTAMP_INVALID`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#checkTimestamp` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / SIG_CONSTRAINTS_FAILURE` |
| Örnek paket | `ESXL1_MM_48` (imza), `ESXL1_MM_47` (mesaj özeti), `ESXL1_MM_70`, `EST_48` |

## Sorunun özeti

İmzanın zaman damgalarından birinin (imza, doğrulama verisi, içerik veya arşiv zaman damgası) imzası doğrulanamıyor ya da mesaj özeti damgalanan veriyle eşleşmiyor. Her imza seviyesinde uygulanır.

## Neden DSS yakalamıyor

DSS bozuk zaman damgasını yalnız damganın kendi sonucunda raporlar; imzacı sertifikası doğrulama anında geçerliyse imza geçer. Strict mode mesaj özeti hatasında imzayı geçersiz sayıyordu ama karar `TOTAL_PASSED` kalıyordu; artık karar bu bulgudan gelir.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "timestampId": "T-…",
  "timestampType": "SIGNATURE_TIMESTAMP",
  "productionTime": "…",
  "tsaSubject": "C=TR,O=TS Signature Forged,CN=TS A2"
}
```

## Giderme

İmzaya geçerli bir zaman damgası alınmalı.

## İlgili

- Tüm kodlar: [README](./README.md)
