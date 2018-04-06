package io.vpv.net.service;

import io.vpv.net.model.CipherConfig;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;
import java.security.SecureRandom;

public class ExecutableComponent implements Runnable {
    private CipherConfig params;
    private SecureRandom rand;
    private KeyManager[] keyManagers;
    private TrustManager[] trustManagers;
    private boolean showHandshakeErrors;
    private boolean stop;
    private boolean showSSLErrors;
    private boolean showErrors;
    private String protocol;
    private String cipherSuite;

    public ExecutableComponent(CipherConfig params, SecureRandom rand, KeyManager[] keyManagers, TrustManager[] trustManagers, boolean showHandshakeErrors, boolean stop, boolean showSSLErrors, boolean showErrors, String protocol, String cipherSuite) {
        this.params = params;
        this.rand = rand;
        this.keyManagers = keyManagers;
        this.trustManagers = trustManagers;
        this.showHandshakeErrors = showHandshakeErrors;
        this.stop = stop;
        this.showSSLErrors = showSSLErrors;
        this.showErrors = showErrors;
        this.protocol = protocol;
        this.cipherSuite = cipherSuite;
    }

    @Override
    public void run() {

    }
}
