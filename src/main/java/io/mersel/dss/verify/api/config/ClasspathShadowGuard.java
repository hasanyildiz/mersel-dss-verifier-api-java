package io.mersel.dss.verify.api.config;

import eu.europa.esig.dss.validation.process.bbb.xcv.sub.checks.KeyUsageCheck;
import org.apache.xml.security.algorithms.implementations.SignatureECDSA;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;

import javax.annotation.PostConstruct;
import java.net.URL;
import java.security.CodeSource;
import java.util.Arrays;
import java.util.List;

/**
 * Sınıfyolu gölgelerinin (bkz. docs/dss-overrides.md) gerçekten yüklendiğini açılışta
 * doğrular. Gölge, bağımlılık jar'ındaki orijinalin yerine ancak uygulama sınıfları
 * sınıfyolunda önce geldiğinde geçer (Spring Boot fat jar: {@code BOOT-INF/classes} →
 * {@code BOOT-INF/lib}). Başka bir başlatma biçiminde orijinal yüklenirse doğrulama
 * kararı sessizce değişir (ör. DER kodlu ECDSA imzaların tamamı geçersiz çıkar); bu
 * durumda uygulama başlamaz.
 */
@Configuration
public class ClasspathShadowGuard {

    private static final Logger LOG = LoggerFactory.getLogger(ClasspathShadowGuard.class);

    static final List<Class<?>> SHADOWS = Arrays.asList(KeyUsageCheck.class, SignatureECDSA.class);

    @PostConstruct
    void verifyShadowsLoaded() {
        for (Class<?> shadow : SHADOWS) {
            if (!sameCodeSource(shadow, ClasspathShadowGuard.class)) {
                throw new IllegalStateException("Sınıfyolu gölgesi etkin değil: " + shadow.getName()
                        + " " + location(shadow) + " konumundan yüklendi, uygulama sınıfları "
                        + location(ClasspathShadowGuard.class) + ". Uygulamayı 'java -jar' ile"
                        + " başlatın veya uygulama sınıflarını sınıfyolunda bağımlılıklardan önce"
                        + " verin (bkz. docs/dss-overrides.md).");
            }
        }
        LOG.info("Sınıfyolu gölgeleri etkin: {}", SHADOWS.size());
    }

    /** İki sınıf aynı kod kaynağından (uygulama sınıfları) mı yüklendi. */
    static boolean sameCodeSource(Class<?> candidate, Class<?> anchor) {
        URL candidateLocation = location(candidate);
        return candidateLocation != null && candidateLocation.toString().equals(String.valueOf(location(anchor)));
    }

    private static URL location(Class<?> type) {
        CodeSource source = type.getProtectionDomain().getCodeSource();
        return source == null ? null : source.getLocation();
    }
}
