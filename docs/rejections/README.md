# Applied Rejections — Mersel DSS Verifier

Mersel DSS Verifier, bir imzayı reddederken Eclipse DSS'in jenerik
`SubIndication` (örn. `SIG_CONSTRAINTS_FAILURE`) çıktısının ötesinde
**Türkiye e-imza ekosistemine özgü, kataloglu, makine-okunaklı bir tanı
kodu** raporlar. İmzanın `valid` alanı yine `false` kalır — yani DSS'in
kararını override etmiyoruz, sadece *neden invalid olduğunu* Mersel
kataloğundan kod + kanıt + dokümantasyon URL'i ile açıklıyoruz.

## Suppression vs Rejection — özet

| Kavram | DSS kararı | Mersel kararı | Verdict değişir mi? | Kullanım |
|---|---|---|---|---|
| **Suppression** | INVALID | VALID | Evet (override) | Type URI yazım hatası gibi, kriptografisi sağlam fakat formal hatası olan imzalara tolerans. |
| **Rejection** | INVALID | INVALID | Hayır (destek) | Tek referanslı XAdES imza (eksik SignedProperties reference) gibi, güvenlik trade-off'u kabul edilmeyen yapısal patolojiler. |

Suppression kataloğu: [`docs/suppressions/`](../suppressions/README.md)

---

## Naming convention

```
MDSS-{LAYER}-{DESCRIPTIVE-SLUG}
```

| Bölüm | Açıklama |
|---|---|
| `MDSS` | Mersel DSS prefix'i. |
| `{LAYER}` | İmza formatı veya kontrol katmanı: `XADES`, `CADES`, `PADES`, `CHAIN`, `CRYPTO`, `TIMESTAMP`, `REVOCATION`, `TR` (Türkiye / MA3 uyum kuralları). |
| `{DESCRIPTIVE-SLUG}` | UPPER-KEBAB-CASE özellik adı; self-documenting. |

Aynı kod hem suppression hem rejection olamaz; kod uzayı paylaşılır.

## Kararlılık (stability)

1. Yayınlanmış bir kod **renaming** edilmez. Davranış değişiyorsa yeni kod
   eklenir, eskisi `@Deprecated` işaretlenir.
2. Her kod için `title`, `defaultReason`, `severity` ve `docsUrl` sabittir.
3. `evidence` map'inde mevcut field'lar removed/renamed yapılmaz; yeni
   field'lar eklenebilir.

## Severity seviyeleri

| Seviye | Anlam | Operatör eylemi |
|---|---|---|
| `ERROR` | İmza reddedildi, kullanıcı eylemi gerekli (yeniden imzalama veya kaynaktan düzeltme). | Kaynak entegratör/firma bilgilendirilmeli, yapısal düzeltme talep edilmeli. |
| `FATAL` | (Gelecekte) Ekosistem güvenlik açığı seviyesinde, derhal blokla. | Alert kurun, root-cause araştırın. |

## Kayıtlı kodlar

| Kod | Severity | Kategori | Açıklama |
|---|---|---|---|
| [`MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE`](./MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE.md) | `ERROR` | XAdES | XAdES imza yalnızca bir `ds:Reference` taşıyor; `SignedProperties` imza kapsamına alınmamış. ETSI EN 319 132-1 iki referans zorunluluğuna aykırı; SignedProperties içindeki alanlar post-signing tahrifata açık. |
| [`MDSS-TR-KEYUSAGE-PROFILE`](./MDSS-TR-KEYUSAGE-PROFILE.md) | `ERROR` | TR uyum | İmzacı sertifikasının OID'lerden tespit edilen profili (e-imza/NES: `digitalSignature` **ve** `nonRepudiation`; mali mühür: yalnız `digitalSignature`) KeyUsage gereksinimini karşılamıyor. DSS sonrası gate; DSS PASSED dese bile reddeder. |
| [`MDSS-TR-XADES-DETACHED`](./MDSS-TR-XADES-DETACHED.md) | `ERROR` | TR uyum (`TR_COMPLIANCE_CHECKS_ENABLED`) | Üst seviye XAdES imza ayrık (detached) ve özgün belgeyle doğrulanamadı: `originalDocument` gönderilmedi ya da ayrık referanslarla eşleşmedi. Özgün belgeyle doğrulanan ayrık imza kabul edilir. |
| [`MDSS-TR-CERT-SIGNATURE-INVALID`](./MDSS-TR-CERT-SIGNATURE-INVALID.md) | `ERROR` | TR uyum (`TR_COMPLIANCE_CHECKS_ENABLED`) | Zincirdeki sertifikanın imzası, aynı DN'li hiçbir aday düzenleyiciyle doğrulanamıyor. |
| [`MDSS-TR-CERT-EXPIRED-AT-SIGNING-TIME`](./MDSS-TR-CERT-EXPIRED-AT-SIGNING-TIME.md) | `ERROR` | TR uyum (`TR_COMPLIANCE_CHECKS_ENABLED`) | İmza zamanında (imza zaman damgası, yoksa beyan edilen zaman) imzacı sertifikasının süresi dolmuş. |
| [`MDSS-TR-CERT-NOT-YET-VALID-AT-SIGNING-TIME`](./MDSS-TR-CERT-NOT-YET-VALID-AT-SIGNING-TIME.md) | `ERROR` | TR uyum (`TR_COMPLIANCE_CHECKS_ENABLED`) | İmza zamanında imzacı sertifikası henüz geçerli değil. |
| [`MDSS-TR-CRL-EXPIRED`](./MDSS-TR-CRL-EXPIRED.md) | `ERROR` | TR uyum (`TR_COMPLIANCE_CHECKS_ENABLED`) | Zincirdeki sertifikanın yalnız SİL'i var ve hiçbirinin `nextUpdate`'i kontrol zamanını kapsamıyor. |
| [`MDSS-TR-NES-CERTIFICATE-POLICY`](./MDSS-TR-NES-CERTIFICATE-POLICY.md) | `ERROR` | TR uyum (`TR_COMPLIANCE_CHECKS_ENABLED`) | NES sertifika politikalarında kullanıcı bildirimi (UserNotice, `1.3.6.1.5.5.7.2.2`) yok. |
| [`MDSS-TR-NES-QC-ETSI`](./MDSS-TR-NES-QC-ETSI.md) | `ERROR` | TR uyum (`TR_COMPLIANCE_CHECKS_ENABLED`) | NES nitelikli sertifika ibarelerinde ETSI QcCompliance `0.4.0.1862.1.1` yok. |
| [`MDSS-TR-NES-QC-BTK`](./MDSS-TR-NES-QC-BTK.md) | `ERROR` | TR uyum (`TR_COMPLIANCE_CHECKS_ENABLED`) | NES nitelikli sertifika ibarelerinde BTK `2.16.792.1.61.0.1.5070.1.1` yok. |
| [`MDSS-TR-SEAL-EXTENDED-KEY-USAGE`](./MDSS-TR-SEAL-EXTENDED-KEY-USAGE.md) | `ERROR` | TR uyum (`TR_COMPLIANCE_CHECKS_ENABLED`) | Mali mühür sertifikasının EKU'sunda `2.16.792.1.2.1.1.5.7.50.1` yok. |
| [`MDSS-TR-SEAL-CERTIFICATE-POLICY`](./MDSS-TR-SEAL-CERTIFICATE-POLICY.md) | `ERROR` | TR uyum (`TR_COMPLIANCE_CHECKS_ENABLED`) | Mali mühür sertifikası `2.16.792.1.2.1.1.5.7.4.1` politikasını taşımıyor. |

## Operasyonel kullanım

### Response içinde tüketim

```jsonc
{
  "signatures": [
    {
      "valid": false,
      "indication": "INDETERMINATE",
      "subIndication": "SIG_CONSTRAINTS_FAILURE",
      "validationErrors": [
        "İmza geçersiz: INDETERMINATE (SIG_CONSTRAINTS_FAILURE)",
        "[MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE] XAdES imza yalnızca bir ds:Reference taşıyor; SignedProperties imza kapsamına alınmamış. SigningTime ve SigningCertificate gibi alanlar kriptografik olarak korunmadığı için post-signing tahrifata açık. ETSI EN 319 132-1 (XAdES-BES) iki referans zorunluluğuna aykırı; imza reddedildi."
      ],
      "appliedRejections": [
        {
          "code": "MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE",
          "title": "XAdES SignedProperties referansı eksik (tek referanslı imza)",
          "severity": "ERROR",
          "originalIndication": "INDETERMINATE",
          "originalSubIndication": "SIG_CONSTRAINTS_FAILURE",
          "evidence": {
            "signedPropertiesId": "SignedProperties_Signature_...",
            "dssBbbConstraint": "BBB_SAV_ISQPMDOSPP",
            "missingProtection": "SigningTime, SigningCertificateV2, SignaturePolicyIdentifier, SignerRole, CommitmentTypeIndication",
            "standardReference": "ETSI EN 319 132-1 (XAdES-BES)",
            "remediation": "İmzayı üreten yazılım iki ds:Reference üretmelidir: biri URI=\"\" (belge body'si, enveloped-signature transform), diğeri URI=\"#<SignedPropertiesId>\" Type=\"http://uri.etsi.org/01903#SignedProperties\" (qualifying properties)."
          },
          "docsUrl": "https://github.com/mersel-dss/mersel-dss-verifier-api-java/blob/main/docs/rejections/MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE.md"
        }
      ]
    }
  ]
}
```

`appliedRejections` boş veya `null` ise: DSS'in jenerik subIndication'ı
tek başına yeterli kabul edildi, ek Türkiye-spesifik bir patoloji tespit
edilmedi.

### Log filter

Her rejection `verification.log`'a `WARN` seviyesinde tek satır kaydeder:

```
TR legacy XAdES rejection raporlandı (signatureId=..., code=MDSS-XADES-LEGACY-TR-MISSING-SP-REFERENCE). ...
```

## Yeni kod eklemek (contributors için)

1. `src/main/java/io/mersel/dss/verify/api/models/enums/RejectionCode.java`
   içine yeni enum değeri ekleyin (naming convention'a uyun).
2. `docs/rejections/<KOD>.md` dosyasını oluşturun.
3. Bu README'deki "Kayıtlı kodlar" tablosuna ekleyin.
4. `RejectionCode.docsUrl` field'ını yeni MD dosyasına yönlendirin
   (GitHub blob URL — `main` branch).
5. Tetik noktasının `@see` javadoc'una enum değerini bağlayın.
6. Service'te detector hit'ini `AppliedRejection`'a maple ve
   `SignatureInfo.appliedRejections` listesine ekle.
