package io.vpv.net.model;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Created by vprasanna on 4/3/18.
 */
public class CipherConfig {
    private int connectTimeout;
    private int readTimeout;
    private boolean hideRejects;
    private String[] sslEnabledProtocols;
    private String[] sslCipherSuites;
    private boolean showHandshakeErrors;
    private boolean showSSLErrors;
    private boolean showErrors;
    private KeyManager[] keyManagers;
    private TrustManager[] trustManagers;
    private int port;
    private String host;
    private InetSocketAddress address;
    private List<String> supportedProtocols;
    private SecureRandom rand;
    private String reportFormat;
    private String errorReportFormat;
    private Set<String> cipherSuites = new HashSet<>();
    private boolean stop = false;
    public CipherConfig() {

    }
    public CipherConfig(int connectTimeout, int readTimeout, boolean hideRejects, String[] sslEnabledProtocols, String[] sslCipherSuites, boolean showHandshakeErrors, boolean showSSLErrors, boolean showErrors, KeyManager[] keyManagers, TrustManager[] trustManagers, int port, String host, InetSocketAddress address, List<String> supportedProtocols, SecureRandom rand, String reportFormat, String errorReportFormat) {
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        this.hideRejects = hideRejects;
        this.sslEnabledProtocols = sslEnabledProtocols;
        this.sslCipherSuites = sslCipherSuites;
        this.showHandshakeErrors = showHandshakeErrors;
        this.showSSLErrors = showSSLErrors;
        this.showErrors = showErrors;
        this.keyManagers = keyManagers;
        this.trustManagers = trustManagers;
        this.port = port;
        this.host = host;
        this.address = address;
        this.supportedProtocols = supportedProtocols;
        this.rand = rand;
        this.reportFormat = reportFormat;
        this.errorReportFormat = errorReportFormat;

    }

    public int getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(int connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public int getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(int readTimeout) {
        this.readTimeout = readTimeout;
    }

    public boolean isHideRejects() {
        return hideRejects;
    }

    public void setHideRejects(boolean hideRejects) {
        this.hideRejects = hideRejects;
    }

    public String[] getSslEnabledProtocols() {
        return sslEnabledProtocols;
    }

    public void setSslEnabledProtocols(String[] sslEnabledProtocols) {
        this.sslEnabledProtocols = sslEnabledProtocols;
    }

    public String[] getSslCipherSuites() {
        return sslCipherSuites;
    }

    public void setSslCipherSuites(String[] sslCipherSuites) {
        this.sslCipherSuites = sslCipherSuites;
    }

    public boolean isShowHandshakeErrors() {
        return showHandshakeErrors;
    }

    public void setShowHandshakeErrors(boolean showHandshakeErrors) {
        this.showHandshakeErrors = showHandshakeErrors;
    }

    public boolean isShowSSLErrors() {
        return showSSLErrors;
    }

    public void setShowSSLErrors(boolean showSSLErrors) {
        this.showSSLErrors = showSSLErrors;
    }

    public boolean isShowErrors() {
        return showErrors;
    }

    public void setShowErrors(boolean showErrors) {
        this.showErrors = showErrors;
    }

    public KeyManager[] getKeyManagers() {
        return keyManagers;
    }

    public void setKeyManagers(KeyManager[] keyManagers) {
        this.keyManagers = keyManagers;
    }

    public TrustManager[] getTrustManagers() {
        return trustManagers;
    }

    public void setTrustManagers(TrustManager[] trustManagers) {
        this.trustManagers = trustManagers;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public InetSocketAddress getAddress() {
        return address;
    }

    public void setAddress(InetSocketAddress address) {
        this.address = address;
    }

    public List<String> getSupportedProtocols() {
        return supportedProtocols;
    }

    public void setSupportedProtocols(List<String> supportedProtocols) {
        this.supportedProtocols = supportedProtocols;
    }

    public SecureRandom getRand() {
        return rand;
    }

    public void setRand(SecureRandom rand) {
        this.rand = rand;
    }

    public String getReportFormat() {
        return reportFormat;
    }

    public void setReportFormat(String reportFormat) {
        this.reportFormat = reportFormat;
    }

    public String getErrorReportFormat() {
        return errorReportFormat;
    }

    public void setErrorReportFormat(String errorReportFormat) {
        this.errorReportFormat = errorReportFormat;
    }

    public Set<String> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(Set<String> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public boolean isStop() {
        return stop;
    }

    public void setStop(boolean stop) {
        this.stop = stop;
    }
}