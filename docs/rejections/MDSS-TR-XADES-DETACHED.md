# MDSS-TR-XADES-DETACHED

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-XADES-DETACHED` |
| Başlık | Ayrık imza özgün belgeyle doğrulanamadı |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_XADES_DETACHED`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`TrComplianceChecker#checkDetached`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/TrComplianceChecker.java) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | Özgün belge yok veya referans eşleşmedi: `INDETERMINATE / SIGNED_DATA_NOT_FOUND`; özet tutmadı: `TOTAL_FAILED / HASH_FAILURE` |
| Örnek paket | `ESXL1_MM_11` (özgün belgesiz) |

## Sorunun özeti

Üst seviye XAdES imza, imzalanan veriye belge dışından (ayrık referansla)
başvuruyor ve imzalanan veri doğrulanamadı. Kural üç durumu ayırır:

| İstek | Sonuç |
|---|---|
| `originalDocument` gönderilmedi | Reddedilir (`INDETERMINATE / SIGNED_DATA_NOT_FOUND`). |
| `originalDocument` gönderildi, her ayrık referans bu belgeyle bulundu ve özeti tuttu | Bu kod üretilmez; karar DSS'indir (DSS geçerli derse imza geçerlidir). |
| `originalDocument` gönderildi, en az bir ayrık referans bulunamadı / özeti tutmadı | Reddedilir (`SIGNED_DATA_NOT_FOUND` / `HASH_FAILURE`). |

"Ayrık referans": `SignedInfo` altında meta tipte olmayan (SignedProperties
vb.), enveloped dönüşümü taşımayan, URI'si boş olmayan ve `#` ile başlamayan
referans. Enveloped ve enveloping imzalar bu kurala girmez; karşı imzalar
kural dışıdır.

Eşleşme DSS diagnostic verisindeki özet eşleştiricilerinden
(`XmlDigestMatcher`: `dataFound`, `dataIntact`) okunur; referans URI'si ham
ve DSS'in decode ettiği biçimle karşılaştırılır. Böylece kabul kararı
politikanın referans kontrollerini (`BBB_CV_IRDOF` / `BBB_CV_IRDOI`) hangi
seviyede tuttuğundan bağımsızdır.

## Neden DSS yakalamıyor

DSS ayrık imzayı geçerli bir biçim sayar; özgün belge gönderilmezse yalnız
"referans verisi bulunamadı" (`BBB_CV_IRDOF`) raporlar ve bu kontrol özel
politikalarda `WARN` seviyesine indirilebilir.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

Özgün belge gönderilmediğinde:

```json
{
  "externalReferenceUris": ["./enveloped-content.xml"],
  "originalDocumentProvided": false
}
```

Özgün belge gönderildi ama eşleşmediğinde:

```json
{
  "externalReferenceUris": ["invoice.xml"],
  "originalDocumentProvided": true,
  "unresolvedReferenceUris": [],
  "digestMismatchReferenceUris": ["invoice.xml"]
}
```

## Giderme

- İmzayı doğrularken imzalanan özgün belgeyi `originalDocument` alanında gönderin.
- Belge gönderildiği halde ret alınıyorsa gönderilen belge imzalanan belge
  değildir ya da imzadan sonra değiştirilmiştir; `digestMismatchReferenceUris` /
  `unresolvedReferenceUris` hangi referansın tutmadığını gösterir.
- e-Fatura için imza faturanın içine (enveloped) yerleştirilmelidir.

## İlgili

- Tüm kodlar: [README](./README.md)
- NES nonRepudiation kuralı bu bayrağa bağlı değildir:
  [`MDSS-TR-KEYUSAGE-PROFILE`](./MDSS-TR-KEYUSAGE-PROFILE.md)
