# MDSS-TR-CRL-EXPIRED

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-CRL-EXPIRED` |
| Başlık | SİL'in geçerlilik süresi dolmuş |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_CRL_EXPIRED`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`TrComplianceChecker#checkCrlValidity`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/TrComplianceChecker.java) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / TRY_LATER` |
| Örnek paket | `ESXL1_MM_17` |

## Sorunun özeti

Zincirdeki bir sertifika için yalnız SİL var ve hiçbirinin `nextUpdate`'i kontrol zamanını (imza zaman damgası, yoksa doğrulama zamanı) kapsamıyor. MA3 `CRLDateChecker` eşdeğeri.

## Neden DSS yakalamıyor

Politikadaki tazelik kuralı WARN; DSS `nextUpdate`'i imza zamanına göre hiç denetlemez. OCSP yanıtı veya kapsayan bir SİL varsa karar DSS'indir.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "…",
  "crlThisUpdate": "…",
  "crlNextUpdate": "…",
  "crlOrigin": "INPUT_DOCUMENT",
  "controlTime": "…",
  "controlTimeSource": "imza zaman damgası"
}
```

## Giderme

İmzaya, imza zamanında geçerli bir SİL veya OCSP yanıtı eklenmelidir.

## İlgili

- Tüm kodlar: [README](./README.md)
- NES nonRepudiation kuralı bu bayrağa bağlı değildir:
  [`MDSS-TR-KEYUSAGE-PROFILE`](./MDSS-TR-KEYUSAGE-PROFILE.md)
