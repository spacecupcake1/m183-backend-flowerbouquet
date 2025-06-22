package com.bbzbl.flowerbouquet.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.security")
public class SecurityHeadersProperties {

    private Csp csp = new Csp();
    private String environment = "development";

    public static class Csp {
        private boolean enabled = true;
        private String reportUri = "";
        private boolean reportOnly = false;

        // Getters and setters
        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }

        public String getReportUri() { return reportUri; }
        public void setReportUri(String reportUri) { this.reportUri = reportUri; }

        public boolean isReportOnly() { return reportOnly; }
        public void setReportOnly(boolean reportOnly) { this.reportOnly = reportOnly; }
    }

    // Getters and setters
    public Csp getCsp() { return csp; }
    public void setCsp(Csp csp) { this.csp = csp; }

    public String getEnvironment() { return environment; }
    public void setEnvironment(String environment) { this.environment = environment; }
}