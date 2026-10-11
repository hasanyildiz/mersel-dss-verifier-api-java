# MDSS-TR-CERT-EXPIRED-AT-SIGNING-TIME

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-CERT-EXPIRED-AT-SIGNING-TIME` |
| Başlık | Sertifikanın süresi dolmuş |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_CERT_EXPIRED_AT_SIGNING_TIME`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`TrComplianceChecker#checkValidityAtSigningTime`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/TrComplianceChecker.java) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / OUT_OF_BOUNDS_NO_POE` |
| Örnek paket | `ESXL1_MM_12` |

## Sorunun özeti

İmza zamanı (en erken bütünlüğü sağlam imza zaman damgası, yoksa imzacının beyan ettiği zaman) imzacı sertifikasının `notAfter` tarihinden sonra.

## Neden DSS yakalamıyor

DSS iptal verisi seçiminde durduğunda (`BBB_XCV_IARDPFC`) süre kontrolüne hiç ulaşmaz.

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
  "signingTimeSource": "imza zaman damgası"
}
```

## Giderme

İmza, imza zamanında geçerli bir sertifikayla atılmalıdır.

## İlgili

- Tüm kodlar: [README](./README.md)
- NES nonRepudiation kuralı bu bayrağa bağlı değildir:
  [`MDSS-TR-KEYUSAGE-PROFILE`](./MDSS-TR-KEYUSAGE-PROFILE.md)
