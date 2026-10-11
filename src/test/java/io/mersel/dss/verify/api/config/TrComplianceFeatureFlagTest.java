package io.mersel.dss.verify.api.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * TR uyum kontrolleri ({@code MDSS-TR-*}) gerçek {@code application.properties}
 * ile varsayılan açıktır; yalnız {@code TR_COMPLIANCE_CHECKS_ENABLED=false} kapatır.
 */
class TrComplianceFeatureFlagTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withUserConfiguration(VerificationConfiguration.class);

    @Test
    @DisplayName("Varsayılan: açık")
    void enabledByDefault() {
        runner.run(context -> assertTrue(context.getBean(VerificationConfiguration.class).isTrComplianceEnabled()));
    }

    @Test
    @DisplayName("Property dosyası yokken de Java varsayılanı açık")
    void enabledByJavaDefault() {
        new ApplicationContextRunner()
                .withUserConfiguration(VerificationConfiguration.class)
                .run(context -> assertTrue(context.getBean(VerificationConfiguration.class).isTrComplianceEnabled()));
    }

    @Test
    @DisplayName("TR_COMPLIANCE_CHECKS_ENABLED=false kapatır")
    void disabledByEnvironment() {
        runner.withPropertyValues("TR_COMPLIANCE_CHECKS_ENABLED=false")
                .run(context -> assertFalse(context.getBean(VerificationConfiguration.class).isTrComplianceEnabled()));
    }

    @Test
    @DisplayName("evaluation profili açık tutar")
    void evaluationProfileKeepsItEnabled() {
        runner.withPropertyValues("spring.profiles.active=evaluation")
                .run(context -> assertTrue(context.getBean(VerificationConfiguration.class).isTrComplianceEnabled()));
    }
}
