/*
 * MERSEL OVERRIDE testi — KeyUsageCheck sınıfyolu gölgesi.
 *
 * Bu test, dss-validation 6.3 jar'ı yerine src/main/java altındaki
 * kopyamızın yüklendiğini varsayar (target/classes bağımlılık jar'ından
 * önce gelir). Orijinal DSS sınıfı OR semantiği taşıdığı için
 * signer_allOf_exactlyOneBitPresent_fails yalnızca gölge ile geçebilir:
 * bu satır aynı zamanda gölgenin etkin olduğunun kanıtıdır.
 */
package eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks;

import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.enumerations.Context;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.Level;
import eu.europa.esig.dss.enumerations.SubContext;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.model.policy.MultiValuesRule;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Gölgelenen {@link KeyUsageCheck} semantiği:
 *
 * <ul>
 *   <li>İmzacı sertifikası ({@code SubContext.SIGNING_CERT}) + birden fazla
 *       beklenen değer → VE: tümü sertifikada olmalı.</li>
 *   <li>CA ({@code SubContext.CA_CERTIFICATE}) ve tek değerli listeler →
 *       orijinal DSS OR davranışı korunur.</li>
 * </ul>
 */
class KeyUsageCheckTest {

    /** Üst sınıf kısıtı private; test için minimal kural uygulaması. */
    private static MultiValuesRule rule(Level level, String... values) {
        return new MultiValuesRule() {
            @Override
            public List<String> getValues() {
                return values.length == 0 ? Collections.emptyList() : Arrays.asList(values);
            }

            @Override
            public Level getLevel() {
                return level;
            }
        };
    }

    /** CertificateWrapper final değildir; yalnızca key usage listesi geçersiz kılınır. */
    private static CertificateWrapper certificateWith(KeyUsageBit... bits) {
        return new CertificateWrapper(new XmlCertificate()) {
            @Override
            public List<KeyUsageBit> getKeyUsages() {
                return bits.length == 0 ? Collections.emptyList() : Arrays.asList(bits);
            }
        };
    }

    private boolean process(CertificateWrapper certificate, SubContext subContext, MultiValuesRule rule) {
        KeyUsageCheck check = new KeyUsageCheck(
                new I18nProvider(), new XmlSubXCV(), certificate,
                Context.SIGNATURE, subContext, rule);
        return check.process();
    }

    // ------------------------------------------------------------------
    // İmzacı sertifikası (SubContext.SIGNING_CERT) — MERSEL AND semantiği
    // ------------------------------------------------------------------

    @Test
    void signer_allOf_bothBitsPresent_passes() {
        assertTrue(process(
                certificateWith(KeyUsageBit.NON_REPUDIATION, KeyUsageBit.DIGITAL_SIGNATURE),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL, "nonRepudiation", "digitalSignature")));
    }

    /** Gölge kanıtı: orijinal DSS (OR) bu vakayı geçirirdi. */
    @Test
    void signer_allOf_exactlyOneBitPresent_fails() {
        assertFalse(process(
                certificateWith(KeyUsageBit.DIGITAL_SIGNATURE),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL, "nonRepudiation", "digitalSignature")));
        assertFalse(process(
                certificateWith(KeyUsageBit.NON_REPUDIATION),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL, "nonRepudiation", "digitalSignature")));
    }

    @Test
    void signer_allOf_unrelatedBitOnly_fails() {
        assertFalse(process(
                certificateWith(KeyUsageBit.KEY_ENCIPHERMENT),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL, "nonRepudiation", "digitalSignature")));
    }

    @Test
    void signer_allOf_missingKeyUsageExtension_fails_likeDss() {
        assertFalse(process(
                certificateWith(),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL, "nonRepudiation", "digitalSignature")));
    }

    @Test
    void signer_allOf_anyValueStarIsNotRequiredExplicitly() {
        // "*" DSS semantiğinde "herhangi bir değer"; AND kümesinden çıkarılır.
        assertTrue(process(
                certificateWith(KeyUsageBit.DIGITAL_SIGNATURE),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL, "*", "digitalSignature")));
    }

    // ------------------------------------------------------------------
    // OR yolu korunur — orijinal DSS davranışı
    // ------------------------------------------------------------------

    @Test
    void signer_singleValue_keepsOrSemantics() {
        assertTrue(process(
                certificateWith(KeyUsageBit.NON_REPUDIATION),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL, "nonRepudiation")));
        assertFalse(process(
                certificateWith(KeyUsageBit.DIGITAL_SIGNATURE),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL, "nonRepudiation")));
    }

    /**
     * Mali mühür politikası (kamusm-strict-constraint.xml) tek Id listeler:
     * mühür sertifikalarında nonRepudiation bulunmaz, yalnız digitalSignature
     * aranır. Örnek paketteki MM A* sertifikaları (EKU 2.16.792.1.2.1.1.5.7.50.1)
     * bu şekildedir.
     */
    @Test
    void maliMuhurPolicy_singleDigitalSignature_sealCertWithoutNonRepudiation_passes() {
        assertTrue(process(
                certificateWith(KeyUsageBit.DIGITAL_SIGNATURE),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL, "digitalSignature")));
        // Anahtar imzalama yetkisi olmayan mühür sertifikası yine geçemez.
        assertFalse(process(
                certificateWith(KeyUsageBit.KEY_ENCIPHERMENT, KeyUsageBit.KEY_AGREEMENT),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL, "digitalSignature")));
    }

    @Test
    void caCertificate_multiValue_keepsOrSemantics() {
        // CA/TSA zincir sertifikaları hiçbir koşulda AND'e düşmez.
        // Dikkat: CRL_SIGN değerinin dizgesi "crlSign"dur (küçük l).
        assertTrue(process(
                certificateWith(KeyUsageBit.CRL_SIGN),
                SubContext.CA_CERTIFICATE,
                rule(Level.FAIL, "keyCertSign", "crlSign")));
        assertFalse(process(
                certificateWith(KeyUsageBit.DIGITAL_SIGNATURE),
                SubContext.CA_CERTIFICATE,
                rule(Level.FAIL, "keyCertSign", "crlSign")));
    }

    @Test
    void signer_emptyExpectation_followsDssEmptySemantics() {
        // Beklenen liste boşken orijinal processValuesCheck'e delege edilir:
        // DSS'te boş beklenti + mevcut değerler → false (kural boş tanımlanmıştır).
        assertFalse(process(
                certificateWith(KeyUsageBit.DIGITAL_SIGNATURE),
                SubContext.SIGNING_CERT,
                rule(Level.FAIL)));
    }

    // ------------------------------------------------------------------
    // Mali mühür: nonRepudiation listelense de aranmaz (ESXL1_MM_37)
    // ------------------------------------------------------------------

    /**
     * Arayüzün eski politika şablonu imzacı için nonRepudiation + digitalSignature
     * listeliyordu; AND semantiğiyle geçerli mali mühür imzası (yalnız
     * digitalSignature) reddediliyordu. Mühür sertifikasında nonRepudiation
     * aranmaz; digitalSignature yine zorunludur.
     */
    @Test
    void sealCertificate_ignoresNonRepudiation_inMultiValueSignerList() {
        CertificateWrapper seal = sealCertificateWith(KeyUsageBit.DIGITAL_SIGNATURE);
        assertTrue(process(seal, SubContext.SIGNING_CERT,
                rule(Level.FAIL, "nonRepudiation", "digitalSignature")));
        assertFalse(process(sealCertificateWith(KeyUsageBit.KEY_ENCIPHERMENT), SubContext.SIGNING_CERT,
                rule(Level.FAIL, "nonRepudiation", "digitalSignature")));
    }

    /** NES / e-imza sertifikasında AND semantiği aynen kalır. */
    @Test
    void nesCertificate_stillNeedsNonRepudiation() {
        CertificateWrapper nes = new CertificateWrapper(new XmlCertificate()) {
            @Override
            public List<KeyUsageBit> getKeyUsages() {
                return Collections.singletonList(KeyUsageBit.DIGITAL_SIGNATURE);
            }

            @Override
            public List<String> getPolicyIds() {
                return Collections.singletonList("2.16.792.1.2.1.1.5.7.1.1");
            }
        };
        assertFalse(process(nes, SubContext.SIGNING_CERT, rule(Level.FAIL, "nonRepudiation", "digitalSignature")));
    }

    private static CertificateWrapper sealCertificateWith(KeyUsageBit... bits) {
        return new CertificateWrapper(new XmlCertificate()) {
            @Override
            public List<KeyUsageBit> getKeyUsages() {
                return Arrays.asList(bits);
            }

            @Override
            public List<String> getPolicyIds() {
                return Collections.singletonList("2.16.792.1.2.1.1.5.7.4.1");
            }
        };
    }
}
