# MDSS-TR-CRL-EXPIRED

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-CRL-EXPIRED` |
| Başlık | SİL'in geçerlilik süresi dolmuş |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_CRL_EXPIRED`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`ValidationDataChecker#evaluateRevocation`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / TRY_LATER` |
| Örnek paket | `ESXL1_MM_17`, `ESXL1_MM_28` (alt kök), `ESXL1_MM_55` / `_77` (zaman damgası) |

## Sorunun özeti

Zincirdeki bir sertifika için yalnız SİL var ve hiçbirinin `nextUpdate`'i kontrol zamanını (imza zaman damgası, yoksa doğrulama zamanı) kapsamıyor. MA3 `CRLDateChecker` eşdeğeri.

BES / ES-T imzada kural DSS'in bulduğu tüm SİL'leri (imzadaki, çevrimiçi; zaman
damgası içindeki SİL yalnız TSA zinciri için) değerlendirir; kapsayan bir SİL veya
OCSP cevabı varsa karar DSS'indir.

Uzun dönemli imzada (`RevocationValues` var, sıkı referans açık —
`TR_STRICT_REFERENCE_ENABLED`) imzacı zinciri için yalnız imzanın kendi
`RevocationValues` SİL'i değerlendirilir: zaman damgası içindeki veya çevrimiçi
geçerli bir SİL süresi dolmuş referans SİL'ini ikame etmez (`ESXL1_MM_28`).
Zaman damgası zinciri için zaman damgasının kendi içindeki SİL de kullanılır;
geçerli hiçbir SİL yoksa damga anı kontrol zamanıdır (`ESXL1_MM_55`).

## Neden DSS yakalamıyor

Politikadaki tazelik kuralı WARN; DSS `nextUpdate`'i imza zamanına göre hiç denetlemez ve
aynı düzenleyicinin başka (zaman damgası içindeki veya çevrimiçi) bir SİL'ini kullanabilir.

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
