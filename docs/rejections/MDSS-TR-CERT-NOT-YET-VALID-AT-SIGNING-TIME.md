# MDSS-TR-CERT-NOT-YET-VALID-AT-SIGNING-TIME

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-CERT-NOT-YET-VALID-AT-SIGNING-TIME` |
| Başlık | Sertifika henüz geçerli değil |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_CERT_NOT_YET_VALID_AT_SIGNING_TIME`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`TrComplianceChecker#checkValidityAtSigningTime`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/TrComplianceChecker.java) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `TOTAL_FAILED / NOT_YET_VALID` |
| Örnek paket | — |

## Sorunun özeti

İmza zamanı (en erken imza zaman damgası, yoksa beyan edilen zaman) imzacı sertifikasının `notBefore` tarihinden önce.

## Neden DSS yakalamıyor

`MDSS-TR-CERT-EXPIRED-AT-SIGNING-TIME` ile aynı: DSS iptal verisi seçiminde durduğunda süre kontrolüne ulaşmaz.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "notBefore": "…",
  "notAfter": "…",
  "signingTime": "…",
  "signingTimeSource": "imzacının beyan ettiği imza zamanı"
}
```

## Giderme

İmzacı saatini ve imza zamanını kontrol edin; imza geçerlilik aralığında atılmalıdır.

## İlgili

- Tüm kodlar: [README](./README.md)
- NES nonRepudiation kuralı bu bayrağa bağlı değildir:
  [`MDSS-TR-KEYUSAGE-PROFILE`](./MDSS-TR-KEYUSAGE-PROFILE.md)
