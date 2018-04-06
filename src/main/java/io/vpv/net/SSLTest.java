package io.vpv.net;

import io.vpv.net.model.CipherConfig;
import io.vpv.net.model.CipherResponse;
import io.vpv.net.service.CipherServiceTestEngine;
import io.vpv.net.util.SSLUtils;
import io.vpv.net.util.TimeUtil;

import javax.crypto.Cipher;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * A driver class to test a server's SSL/TLS support.
 * <p/>
 * Usage: java SSLTest [opts] host[:port]
 * <p/>
 * Try "java SSLTest -h" for help.
 * <p/>
 * This tester will attempts to handshake with the target host with all
 * available protocols and ciphers and report which ones were accepted and
 * which were rejected. An HTTP connection is never fully made, so these
 * connections should not flood the host's access log with entries.
 *
 * @author Christopher Schultz/Venkateswara VP
 */
public class SSLTest {

    static final CipherServiceTestEngine testEngine = new CipherServiceTestEngine();

    private static void usage() {
        System.out.println("Usage: java " + SSLTest.class + " [opts] host[:port]");
        System.out.println();
        System.out.println("-sslprotocol                 Sets the SSL/TLS protocol to be used (e.g. SSL, TLS, SSLv3, TLSv1.2, etc.)");
        System.out.println("-enabledprotocols protocols  Sets individual SSL/TLS ptotocols that should be enabled");
        System.out.println("-ciphers cipherspec          A comma-separated list of SSL/TLS ciphers");
        System.out.println();
        System.out.println("-keystore                    Sets the key store for connections (for TLS client certificates)");
        System.out.println("-keystoretype type           Sets the type for the key store");
        System.out.println("-keystorepassword pass       Sets the password for the key store");
        System.out.println("-keystoreprovider provider   Sets the crypto provider for the key store");
        System.out.println();
        System.out.println("-truststore                  Sets the trust store for connections");
        System.out.println("-truststoretype type         Sets the type for the trust store");
        System.out.println("-truststorepassword pass     Sets the password for the trust store");
        System.out.println("-truststorealgorithm alg     Sets the algorithm for the trust store");
        System.out.println("-truststoreprovider provider Sets the crypto provider for the trust store");
        System.out.println("-crlfilename                 Sets the CRL filename to use for the trust store");
        System.out.println();
        System.out.println("-check-certificate           Checks certificate trust (default: false)");
        System.out.println("-no-check-certificate        Ignores certificate errors (default: true)");
        System.out.println("-verify-hostname             Verifies certificate hostname (default: false)");
        System.out.println("-no-verify-hostname          Ignores hostname mismatches (default: true)");
        System.out.println();
        System.out.println("-showsslerrors               Show SSL/TLS error details");
        System.out.println("-showhandshakeerrors         Show SSL/TLS handshake error details");
        System.out.println("-showerrors                  Show all connection error details");
        System.out.println("-hiderejects                 Only show protocols/ciphers which were successful");
        System.out.println("-showcerts                   Shows some basic Certificate details");
        System.out.println();
        System.out.println("-h -help --help              Shows this help message");
    }

    public static void main(String[] args)
            throws Exception {
        long startTime = System.currentTimeMillis();
        // Enable all algorithms + protocols
        // System.setProperty("jdk.tls.client.protocols", "SSLv2Hello,SSLv3,TLSv1,TLSv1.1,TLSv1.2");
        Security.setProperty("jdk.tls.disabledAlgorithms", "");
        Security.setProperty("crypto.policy", "unlimited"); // For Java 9+

        int connectTimeout = 0; // default = infinite
        int readTimeout = 1000;

        boolean disableHostnameVerification = true;
        boolean disableCertificateChecking = true;
        boolean hideRejects = false;

        String trustStoreFilename = System.getProperty("javax.net.ssl.trustStore");
        String trustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");
        String trustStoreType = System.getProperty("javax.net.ssl.trustStoreType");
        String trustStoreProvider = System.getProperty("javax.net.ssl.trustStoreProvider");
        String trustStoreAlgorithm = null;
        String keyStoreFilename = System.getProperty("javax.net.ssl.keyStore");
        String keyStorePassword = System.getProperty("javax.net.ssl.keyStorePassword");
        String keyStoreType = System.getProperty("javax.net.ssl.keyStoreType");
        String keyStoreProvider = System.getProperty("javax.net.ssl.keyStoreProvider");
        String sslProtocol = "TLS";
        String[] sslEnabledProtocols = null; // new String[] { "SSLv2", "SSLv2hello", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2" };
        String[] sslCipherSuites = null; // Default = default for protocol
        String crlFilename = null;
        boolean showCerts = false;
        boolean connectOnly = false;
        boolean showHandshakeErrors = false;
        boolean showSSLErrors = false;
        boolean showErrors = false;

        if (args.length < 1) {
            usage();
            System.exit(0);
        }

        int argIndex;
        for (argIndex = 0; argIndex < args.length; ++argIndex) {
            String arg = args[argIndex];

            if (!arg.startsWith("-"))
                break;
            else if ("--".equals(arg))
                break;
            else if ("-no-check-certificate".equals(arg))
                disableCertificateChecking = true;
            else if ("-check-certificate".equals(arg))
                disableCertificateChecking = false;
            else if ("-no-verify-hostname".equals(arg))
                disableHostnameVerification = true;
            else if ("-verify-hostname".equals(arg))
                disableHostnameVerification = false;
            else if ("-sslprotocol".equals(arg))
                sslProtocol = args[++argIndex];
            else if ("-enabledprotocols".equals(arg))
                sslEnabledProtocols = args[++argIndex].split("\\s*,\\s*");
            else if ("-ciphers".equals(arg))
                sslCipherSuites = args[++argIndex].split("\\s*,\\s*");
            else if ("-connecttimeout".equals(arg))
                connectTimeout = Integer.parseInt(args[++argIndex]);
            else if ("-readtimeout".equals(arg))
                readTimeout = Integer.parseInt(args[++argIndex]);
            else if ("-truststore".equals(arg))
                trustStoreFilename = args[++argIndex];
            else if ("-truststoretype".equals(arg))
                trustStoreType = args[++argIndex];
            else if ("-truststorepassword".equals(arg))
                trustStorePassword = args[++argIndex];
            else if ("-truststoreprovider".equals(arg))
                trustStoreProvider = args[++argIndex];
            else if ("-truststorealgorithm".equals(arg))
                trustStoreAlgorithm = args[++argIndex];
            else if ("-crlfilename".equals(arg))
                crlFilename = args[++argIndex];
            else if ("-keystore".equals(arg))
                keyStoreFilename = args[++argIndex];
            else if ("-keystoretype".equals(arg))
                keyStoreType = args[++argIndex];
            else if ("-keystorepassword".equals(arg))
                keyStorePassword = args[++argIndex];
            else if ("-keystoreprovider".equals(arg))
                keyStoreProvider = args[++argIndex];
            else if ("-showcerts".equals(arg))
                showCerts = true;
            else if ("-showerrors".equals(arg))
                showErrors = showHandshakeErrors = showSSLErrors = true;
            else if ("-showhandshakeerrors".equals(arg))
                showHandshakeErrors = true;
            else if ("-showsslerrors".equals(arg))
                showSSLErrors = true;
            else if ("-connectonly".equals(arg))
                connectOnly = true;
            else if ("-hiderejects".equals(arg))
                hideRejects = true;
            else if ("--help".equals(arg)
                    || "-h".equals(arg)
                    || "-help".equals(arg)) {
                usage();
                System.exit(0);
            } else {
                System.err.println("Unrecognized option: " + arg);
                System.exit(1);
            }
        }

        if (argIndex >= args.length) {
            System.err.println("Unexpected additional arguments: "
                    + java.util.Arrays.asList(args).subList(argIndex, args.length));

            usage();
            System.exit(1);
        }

        // TODO: Does this actually do anything?
        if (disableHostnameVerification)
            SSLUtils.disableSSLHostnameVerification();

        KeyManager[] keyManagers;
        TrustManager[] trustManagers;

        if (null != keyStoreFilename) {
            if (null == keyStoreType)
                keyStoreType = "JKS";

            KeyStore keyStore = SSLUtils.getStore(keyStoreFilename, keyStorePassword, keyStoreType, keyStoreProvider);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            char[] kpwd;
            if (null != keyStorePassword && 0 < keyStorePassword.length())
                kpwd = keyStorePassword.toCharArray();
            else
                kpwd = null;
            kmf.init(keyStore, kpwd);
            keyManagers = kmf.getKeyManagers();
        } else
            keyManagers = null;

        if (disableCertificateChecking
                || "true".equalsIgnoreCase(System.getProperty("disable.ssl.cert.checks"))) {
            trustManagers = SSLUtils.getTrustAllCertsTrustManagers();
        } else if (null != trustStoreFilename) {
            if (null == trustStoreType)
                trustStoreType = "JKS";

            trustManagers = SSLUtils.getTrustManagers(trustStoreFilename, trustStorePassword, trustStoreType, trustStoreProvider, trustStoreAlgorithm, null, crlFilename);
        } else
            trustManagers = null;

        int port = 443;
        String host = args[argIndex];

        int pos = host.indexOf(':');
        if (pos > 0) {
            port = Integer.parseInt(host.substring(pos + 1));
            host = host.substring(0, pos);
        }

        try {
            InetAddress[] iaddrs = InetAddress.getAllByName(host);
            if (null == iaddrs || 0 == iaddrs.length) {
                System.err.println("Unknown hostname: " + host);
                System.exit(1);
            }
            if (1 == iaddrs.length)
                System.out.println("Host [" + host + "] resolves to address [" + iaddrs[0].getHostAddress() + "]");
            else {
                System.out.print("Host [" + host + "] resolves to addresses ");
                for (int i = 0; i < iaddrs.length; ++i) {
                    if (i > 0) System.out.print(", ");
                    System.out.print("[" + iaddrs[i].getHostAddress() + "]");
                }
                System.out.println();
            }
        } catch (UnknownHostException uhe) {
            System.err.println("Unknown hostname: " + host);
            System.exit(1);
        }

        InetSocketAddress address = new InetSocketAddress(host, port);
        if (address.isUnresolved()) {
            System.err.println("Unknown hostname: " + host);
            System.exit(1);
        }

        List<String> supportedProtocols;

        if (null == sslEnabledProtocols) {
            // Auto-detect supported protocols
            ArrayList<String> protocols = new ArrayList<String>();
            // TODO: Allow the specification of a specific provider (or set?)
            for (Provider provider : Security.getProviders()) {
                for (Object prop : provider.keySet()) {
                    String key = (String) prop;
                    if (key.startsWith("SSLContext.")
                            && !"SSLContext.Default".equals(key)
                            && key.matches(".*[0-9].*"))
                        protocols.add(key.substring("SSLContext.".length()));
                    else if (key.startsWith("Alg.Alias.SSLContext.")
                            && key.matches(".*[0-9].*"))
                        protocols.add(key.substring("Alg.Alias.SSLContext.".length()));
                }
            }
            Collections.sort(protocols); // Should give us a nice sort-order by default
            System.out.println("Auto-detected client-supported protocols: " + protocols);
            supportedProtocols = protocols;
            sslEnabledProtocols = supportedProtocols.toArray(new String[supportedProtocols.size()]);
        } else {
            supportedProtocols = new ArrayList<String>(Arrays.asList(sslEnabledProtocols));
        }

        // Warn about operating under limited cryptographic controls.
        if (Integer.MAX_VALUE > Cipher.getMaxAllowedKeyLength("foo"))
            System.err.println("[warning] Client is running under LIMITED cryptographic controls. Consider installing the JCE Unlimited Strength Jurisdiction Policy Files.");

        System.out.println("Testing server " + host + ":" + port);

        SecureRandom rand = SecureRandom.getInstance("NativePRNG");

        String reportFormat = "%9s %8s %s%n";
        String errorReportFormat = "%9s %8s %s %s%n";
        System.out.print(String.format(reportFormat, "Supported", "Protocol", "Cipher"));

        if (connectOnly) {
            sslEnabledProtocols = new String[0];
        }

        CipherConfig cipherConfig = new CipherConfig();
        cipherConfig.setConnectTimeout(connectTimeout);
        cipherConfig.setReadTimeout(readTimeout);
        cipherConfig.setHideRejects(hideRejects);
        cipherConfig.setSslEnabledProtocols(sslEnabledProtocols);
        cipherConfig.setSslCipherSuites(sslCipherSuites);
        cipherConfig.setShowHandshakeErrors(showHandshakeErrors);
        cipherConfig.setShowSSLErrors(showSSLErrors);
        cipherConfig.setShowErrors(showErrors);
        cipherConfig.setKeyManagers(keyManagers);
        cipherConfig.setTrustManagers(trustManagers);
        cipherConfig.setPort(port);
        cipherConfig.setHost(host);
        cipherConfig.setAddress(address);
        cipherConfig.setSupportedProtocols(supportedProtocols);
        cipherConfig.setRand(rand);
        cipherConfig.setReportFormat(reportFormat);
        cipherConfig.setErrorReportFormat(errorReportFormat);

        cipherProbe(cipherConfig);

        if (supportedProtocols.isEmpty()) {
            System.err.println("This client supports none of the requested protocols: "
                    + Arrays.asList(sslEnabledProtocols));
            System.err.println("Exiting.");
            System.exit(1);
        }

        // Now get generic and allow the server to decide on the protocol and cipher suite
        String[] protocolsToTry = supportedProtocols.toArray(new String[supportedProtocols.size()]);

        // If the user didn't provide a specific set of cipher suites,
        // use the system's *complete* set of supported cipher suites.
        if (null == sslCipherSuites)
            sslCipherSuites = testEngine.getJVMSupportedCipherSuites(sslProtocol, rand);

        SSLSocketFactory sf = SSLUtils.getSSLSocketFactory(sslProtocol,
                protocolsToTry,
                sslCipherSuites,
                rand,
                trustManagers,
                keyManagers);

        performBasicConnectivityTest(connectTimeout, readTimeout, showCerts, port, host, address, supportedProtocols, sf);

        System.out.println(String.format("Total Execution time: %s", TimeUtil.formatElapsedTime(System.currentTimeMillis() - startTime)));
    }

    private static void performBasicConnectivityTest(int connectTimeout, int readTimeout, boolean showCerts, int port, String host, InetSocketAddress address, List<String> supportedProtocols, SSLSocketFactory sf) throws IOException {
        SSLSocket socket = null;

        try {
            socket = testEngine.createSSLSocket(address, host, port, connectTimeout, readTimeout, sf);
            socket.startHandshake();

            System.out.print("Given this client's capabilities ("
                    + supportedProtocols
                    + "), the server prefers protocol=");
            System.out.print(socket.getSession().getProtocol());
            System.out.print(", cipher=");
            System.out.println(socket.getSession().getCipherSuite());

            if (showCerts) {
                showCertificateDetails(socket);
            }
        } catch (SocketException se) {
            System.out.println("Error during connection handshake for protocols "
                    + supportedProtocols
                    + ": server likely does not support any of these protocols.");

            if (showCerts)
                System.out.println("Unable to show server certificate without a successful handshake.");
        } catch (CertificateParsingException e) {
            System.out.println("Unable to get the certificate details:" + e.getLocalizedMessage());
            e.printStackTrace();
        } finally {
            if (null != socket) try {
                socket.close();
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }
        }
    }

    private static void showCertificateDetails(SSLSocket socket) throws SSLPeerUnverifiedException, CertificateParsingException {
        System.out.println("Attempting to check certificate:");
        for (Certificate cert : socket.getSession().getPeerCertificates()) {
            String certType = cert.getType();
            System.out.println("Certificate: " + certType);
            if ("X.509".equals(certType)) {
                X509Certificate x509 = (X509Certificate) cert;
                System.out.println("Subject: " + x509.getSubjectDN());
                System.out.println("Issuer: " + x509.getIssuerDN());
                System.out.println("Serial: " + x509.getSerialNumber());
                try {
                    x509.checkValidity();
                    System.out.println("Certificate is currently valid.");
                } catch (CertificateException ce) {
                    System.out.println("WARNING: certificate is not valid: " + ce.getMessage());
                }
//               System.out.println("Signature: " + testEngine.toHexString(x509.getSignature()));
//               System.out.println("cert bytes: " + testEngine.toHexString(cert.getEncoded()));
//               System.out.println("cert bytes: " + cert.getPublicKey());
                System.out.println("Alternate Names: " + getAlternativeNames(x509.getSubjectAlternativeNames()));

            } else {
                System.out.println("Unknown certificate type (" + cert.getType() + "): " + cert);
            }
        }
    }

    private static String getAlternativeNames(Collection<List<?>> subjectAlternativeNames) {
        final StringBuilder builder = new StringBuilder();
        if (null != subjectAlternativeNames && subjectAlternativeNames.size() != 0) {
            subjectAlternativeNames.stream()
                    .map(list -> {
                        if (null != list && list.size() >= 2) {
                            return list.get(1);
                        } else {
                            return null;
                        }
                    }).filter(value -> value != null)
                    .forEach(name -> {
                        if (builder.length() > 0) {
                            builder.append(", ").append(name);
                        } else {
                            builder.append(name);
                        }
                    });
        } else {
            builder.append("Unavailable");
        }

        return builder.toString();
    }

    private static void cipherProbe(CipherConfig params) {
        List<CipherResponse> responses = testEngine.invoke(params);

        //Print them
        responses.stream()
                .forEach(response -> {
                    if (null != response.getError())
                        System.out.print(String.format(params.getErrorReportFormat(),
                                response.getStatus(),
                                response.getProtocol(),
                                response.getName(),
                                response.getError()));
                    else if (!params.isHideRejects() || !"Rejected".equals(response.getStatus()))
                        System.out.print(String.format(params.getReportFormat(),
                                response.getStatus(),
                                response.getProtocol(),
                                response.getName()));
                });
    }


}