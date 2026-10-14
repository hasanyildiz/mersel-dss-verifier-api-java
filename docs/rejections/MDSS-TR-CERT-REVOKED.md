# MDSS-TR-CERT-REVOKED

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-CERT-REVOKED` |
| Başlık | Sertifika iptal edilmiş |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_CERT_REVOKED`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | `ValidationDataChecker#evaluateRevocation` ([`ValidationDataChecker`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/ValidationDataChecker.java)) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (her seviyede, esnek); uzun dönemli imzada ayrıca `verification.tr-compliance.strict-reference-enabled` / `TR_STRICT_REFERENCE_ENABLED` (sıkı) — ikisi de default `true` |
| DSS PASSED iken verdict | Alt kök: `INDETERMINATE / REVOKED_CA_NO_POE`; diğer: `INDETERMINATE / REVOKED_NO_POE` |
| Örnek paket | `ESXL1_MM_27` (alt kök, SİL), `ESXL1_MM_30` (alt kök, OCSP), `ESXL1_MM_51` / `_73` (zaman damgası) |

## Sorunun özeti

İmzadaki iptal verisine göre zincirdeki bir sertifika kontrol zamanında veya öncesinde iptal edilmiş:

- imzacı zinciri (alt kök) için kontrol zamanı imza zaman damgasıdır,
- zaman damgası zinciri için damganın üretim zamanıdır.

Sertifika kontrol zamanından **sonra** iptal edildiyse imza geçerlidir; imzacı
dışındaki sertifikalar için `ARCHIVE_REQUIRED_REVOCATION_EVIDENCE` önerisi
verilir (`ESXL1_MM_44`, `_45`, `_52`).

## Neden DSS yakalamıyor

Politikada alt kök ve zaman damgası sertifikası için `NotRevoked` WARN'dur; DSS iptali raporlar ama imzayı geçirir.

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

## Esnek mod (BES / ES-T)

İmza `RevocationValues` taşımıyorsa (veya sıkı referans kapalıysa) aynı kural DSS'in
bulduğu iptal verisiyle (imzadaki ve çevrimiçi / önbellekteki veri; zaman damgası
içindeki veri yalnız TSA zinciri için) çalışır: geçerli bir veri yeterlidir ve veri
yokluğu tek başına ret nedeni değildir. Ret yalnız olumlu kanıtla verilir: sertifika
kontrol zamanından önce iptal edilmiş ya da bulunan verinin hiçbiri kabul edilebilir
değil (`BES_27`, `EST_27`, `EST_51`, `EST_55`).

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "C=TR,O=Revoked in CRL,CN=SubRoot A3",
  "role": "CA",
  "revocationDate": "2019-05-30T09:00:11Z",
  "revocationSource": "SİL"
}
```

## Giderme

İmza geçerli bir sertifika zinciriyle yeniden oluşturulmalı.

## İlgili

- Tüm kodlar: [README](./README.md)
