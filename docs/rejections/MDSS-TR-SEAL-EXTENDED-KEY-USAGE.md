# MDSS-TR-SEAL-EXTENDED-KEY-USAGE

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-SEAL-EXTENDED-KEY-USAGE` |
| Başlık | Mali mühür anahtar kullanımı kontrolü başarısız |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_SEAL_EXTENDED_KEY_USAGE`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`TrComplianceChecker#checkCertificateProfile`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/TrComplianceChecker.java) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / CHAIN_CONSTRAINTS_FAILURE` |
| Örnek paket | `*_38` (MM A1 2, "Enhanced Key Usage Absent") |

## Sorunun özeti

Mali mühür sertifikası (politika `2.16.792.1.2.1.1.5.7.4.1`) genişletilmiş anahtar kullanımında (EKU) mali mühür OID'i `2.16.792.1.2.1.1.5.7.50.1` taşımıyor.

## Neden DSS yakalamıyor

DSS'in `<ExtendedKeyUsage>` kısıtı politika genelindedir; açılırsa EKU taşımayan geçerli NES imzalarını da reddeder.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "C=TR,O=Enhanced Key Usage Absent,CN=MM A1 2",
  "certificatePolicies": [
    "2.16.792.1.2.1.1.5.7.4.1"
  ],
  "extendedKeyUsages": []
}
```

## Giderme

Mali mühür akışında mali mühür EKU'sunu taşıyan sertifika kullanın.

## İlgili

- Tüm kodlar: [README](./README.md)
- NES nonRepudiation kuralı bu bayrağa bağlı değildir:
  [`MDSS-TR-KEYUSAGE-PROFILE`](./MDSS-TR-KEYUSAGE-PROFILE.md)
