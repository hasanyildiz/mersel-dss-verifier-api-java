package io.mersel.dss.verify.api.config;

import org.apache.xml.security.Init;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Gölgeler uygulama sınıflarıyla aynı yerden yüklenir; bağımlılık jar'ından gelen
 * sınıf (xmlsec {@link Init}) gölge sayılmaz.
 */
class ClasspathShadowGuardTest {

    @Test
    @DisplayName("Gölgeler etkin: açılış kontrolü geçer")
    void shadowsLoadedFromApplicationClasses() {
        for (Class<?> shadow : ClasspathShadowGuard.SHADOWS) {
            assertTrue(ClasspathShadowGuard.sameCodeSource(shadow, ClasspathShadowGuard.class), shadow.getName());
        }
        assertDoesNotThrow(() -> new ClasspathShadowGuard().verifyShadowsLoaded());
    }

    @Test
    @DisplayName("Bağımlılık jar'ından yüklenen sınıf gölge sayılmaz")
    void dependencyClassIsNotShadow() {
        assertFalse(ClasspathShadowGuard.sameCodeSource(Init.class, ClasspathShadowGuard.class));
        assertFalse(ClasspathShadowGuard.sameCodeSource(String.class, ClasspathShadowGuard.class));
    }
}
