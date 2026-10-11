# MDSS-TR-NES-QC-BTK

| Alan | Değer |
|---|---|
| Kod | `MDSS-TR-NES-QC-BTK` |
| Başlık | NES nitelikli sertifika ibaresi (BTK) eksik |
| Severity | `ERROR` |
| Layer | TR uyum (DSS sonrası) |
| İlgili enum | [`RejectionCode.MDSS_TR_NES_QC_BTK`](../../src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java) |
| Tetik noktası | [`TrComplianceChecker#checkCertificateProfile`](../../src/main/java/io/mersel/dss/verify/api/services/compliance/TrComplianceChecker.java) |
| Config | `verification.tr-compliance.enabled` / `TR_COMPLIANCE_CHECKS_ENABLED` (default: `true`; `false` kapatır) |
| DSS PASSED iken verdict | `INDETERMINATE / CHAIN_CONSTRAINTS_FAILURE` |
| Örnek paket | `ESXL1_MM_10` (QC A1 6, "BTK QC Statement ID Absent") |

## Sorunun özeti

İmzacı NES sertifikasının `qcStatements` uzantısında BTK ibaresi `2.16.792.1.61.0.1.5070.1.1` yok (ETSI ibaresi var).

### OID'ler ne anlama geliyor

**OID** (Object Identifier), dünya çapında tekil, noktalı bir sayı
dizisidir; sertifikalar "ne olduklarını" bu numaralarla beyan eder. NES
sertifikasında nitelik beyanı iki uzantıda durur:

| Uzantı | OID | NES'te beklenen içerik |
|---|---|---|
| `certificatePolicies` | `2.5.29.32` | Politika OID'i (KamuSM NES: `2.16.792.1.2.1.1.5.7.1.1`) ve altında **kullanıcı bildirimi** (UserNotice, `1.3.6.1.5.5.7.2.2`): "Bu sertifika, 5070 sayılı Elektronik İmza Kanununa göre nitelikli elektronik sertifikadır." |
| `qcStatements` (RFC 3739) | `1.3.6.1.5.5.7.1.3` | Nitelikli sertifika ibareleri: **ETSI** `0.4.0.1862.1.1` (`id-etsi-qcs-QcCompliance`, ETSI EN 319 412-5 — "nitelikli sertifika olarak düzenlendi") ve **BTK** `2.16.792.1.61.0.1.5070.1.1` (ulusal 5070 sayılı Kanun ibaresi, aynı Türkçe metinle). |

Mali mühür sertifikaları bu ibarelerin hiçbirini taşımaz; bu yüzden kural
yalnızca mali mühür olmayan imzacılara uygulanır.

## Neden DSS yakalamıyor

DSS bu ulusal ibareyi yalnız "diğer QC ibaresi" (`CertificateWrapper#getOtherQcStatements`) olarak listeler; politika şemasında bu OID'i zorunlu kılan bir kısıt yoktur.

Bu kod DSS PASSED dediğinde de imzayı reddeder ve imzanın `rootCause`
alanı olur; DSS'in asıl kararı `AppliedRejection.originalIndication`
alanında saklanır. DSS zaten reddetmişse DSS verdict'i korunur, bu kod
yalnızca kök nedeni belirler.

## Kanıt alanları (`AppliedRejection.evidence`)

```json
{
  "certificateSubject": "2.5.4.5=#130b3131313131313131313131,C=TR,O=BTK QC Statement ID Absent,CN=QC A1 6",
  "certificatePolicies": [
    "2.16.792.1.2.1.1.5.7.1.1"
  ],
  "keyUsages": [
    "digitalSignature",
    "nonRepudiation"
  ],
  "qcStatements": [
    "1.3.6.1.5.5.7.11.1",
    "0.4.0.1862.1.1"
  ]
}
```

## Giderme

İmza, 5070 sayılı Kanun BTK ibaresini taşıyan nitelikli sertifikayla atılmalıdır.

## İlgili

- Tüm kodlar: [README](./README.md)
- NES nonRepudiation kuralı bu bayrağa bağlı değildir:
  [`MDSS-TR-KEYUSAGE-PROFILE`](./MDSS-TR-KEYUSAGE-PROFILE.md)
