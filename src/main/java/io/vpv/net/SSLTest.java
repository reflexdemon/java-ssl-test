package io.vpv.net;

import io.vpv.net.model.CipherConfig;
import io.vpv.net.model.CipherResponse;
import io.vpv.net.service.CipherServiceTestEngine;
import io.vpv.net.util.ColorPrintUtil;
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
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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

    private static final SimpleDateFormat DATA_FORMAT = new SimpleDateFormat("EEE, MMM dd yyyy 'at' hh:mm:ss aaa z");
    static final CipherServiceTestEngine testEngine = new CipherServiceTestEngine();
    /**
     * The executor.
     */
    private static final ExecutorService executor = Executors
            .newFixedThreadPool(10);
    private static void usage() {
        ColorPrintUtil.printKeyValue("Usage:", " javassltest [opts] host[:port]");
        System.out.println();
        ColorPrintUtil.println("Options:");
        ColorPrintUtil.printKeyValue("-sslprotocol", "                 Sets the SSL/TLS protocol to be used (e.g. SSL, TLS, SSLv3, TLSv1.2, etc.)");
        ColorPrintUtil.printKeyValue("-enabledprotocols protocols", "  Sets individual SSL/TLS ptotocols that should be enabled");
        ColorPrintUtil.printKeyValue("-ciphers cipherspec", "          A comma-separated list of SSL/TLS ciphers");
        System.out.println();
        ColorPrintUtil.printKeyValue("-keystore", "                    Sets the key store for connections (for TLS client certificates)");
        ColorPrintUtil.printKeyValue("-keystoretype type", "           Sets the type for the key store");
        ColorPrintUtil.printKeyValue("-keystorepassword pass", "       Sets the password for the key store");
        ColorPrintUtil.printKeyValue("-keystoreprovider provider", "   Sets the crypto provider for the key store");
        System.out.println();
        ColorPrintUtil.printKeyValue("-truststore", "                  Sets the trust store for connections");
        ColorPrintUtil.printKeyValue("-truststoretype type", "         Sets the type for the trust store");
        ColorPrintUtil.printKeyValue("-truststorepassword pass", "     Sets the password for the trust store");
        ColorPrintUtil.printKeyValue("-truststorealgorithm alg", "     Sets the algorithm for the trust store");
        ColorPrintUtil.printKeyValue("-truststoreprovider provider", " Sets the crypto provider for the trust store");
        ColorPrintUtil.printKeyValue("-crlfilename", "                 Sets the CRL filename to use for the trust store");
        System.out.println();
        ColorPrintUtil.printKeyValue("-check-certificate", "           Checks certificate trust (default: false)");
        ColorPrintUtil.printKeyValue("-no-check-certificate", "        Ignores certificate errors (default: true)");
        ColorPrintUtil.printKeyValue("-verify-hostname", "             Verifies certificate hostname (default: false)");
        ColorPrintUtil.printKeyValue("-no-verify-hostname", "          Ignores hostname mismatches (default: true)");
        System.out.println();
        ColorPrintUtil.printKeyValue("-showsslerrors", "               Show SSL/TLS error details");
        ColorPrintUtil.printKeyValue("-showhandshakeerrors", "         Show SSL/TLS handshake error details");
        ColorPrintUtil.printKeyValue("-showerrors", "                  Show all connection error details");
        ColorPrintUtil.printKeyValue("-hiderejects", "                 Only show protocols/ciphers which were successful");
        ColorPrintUtil.printKeyValue("-showcerts", "                   Shows some basic Certificate details");
        System.out.println();
        ColorPrintUtil.printKeyValue("-h -help --help", "              Shows this help message");
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
                ColorPrintUtil.printErrln("Unrecognized option: " + arg);
                System.exit(1);
            }
        }

        if (argIndex >= args.length) {
            ColorPrintUtil.printErrln("Unexpected additional arguments: "
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
                ColorPrintUtil.printErrln("Unknown hostname: " + host);
                System.exit(1);
            }
            if (1 == iaddrs.length) {
                ColorPrintUtil.print("Host [", ColorPrintUtil.COLOR_BLUE);
                ColorPrintUtil.print(host, ColorPrintUtil.COLOR_BLUE_BOLD);
                ColorPrintUtil.print("] resolves to address [", ColorPrintUtil.COLOR_BLUE);
                ColorPrintUtil.print(iaddrs[0].getHostAddress(), ColorPrintUtil.COLOR_BLUE_BOLD);
                ColorPrintUtil.print("]", ColorPrintUtil.COLOR_BLUE);
                System.out.println();
            } else {
                ColorPrintUtil.print("Host [", ColorPrintUtil.COLOR_BLUE);
                ColorPrintUtil.print(host, ColorPrintUtil.COLOR_BLUE_BOLD);
                ColorPrintUtil.print("] resolves to address ", ColorPrintUtil.COLOR_BLUE);
                for (int i = 0; i < iaddrs.length; ++i) {
                    if (i > 0) System.out.print(", ");
                    ColorPrintUtil.print("[" + iaddrs[i].getHostAddress() + "]", ColorPrintUtil.COLOR_BLUE_BOLD);
                }
                System.out.println();
            }
        } catch (UnknownHostException uhe) {
            ColorPrintUtil.printErrln("Unknown hostname: " + host);
            System.exit(1);
        }

        InetSocketAddress address = new InetSocketAddress(host, port);
        if (address.isUnresolved()) {
            ColorPrintUtil.printErrln("Unknown hostname: " + host);
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
            ColorPrintUtil.printKeyValue("Auto-detected client-supported protocols: " , protocols.toString());
            supportedProtocols = protocols;
            sslEnabledProtocols = supportedProtocols.toArray(new String[supportedProtocols.size()]);
        } else {
            supportedProtocols = new ArrayList<String>(Arrays.asList(sslEnabledProtocols));
        }

        // Warn about operating under limited cryptographic controls.
        if (Integer.MAX_VALUE > Cipher.getMaxAllowedKeyLength("foo"))
            ColorPrintUtil.printErrln("[warning] Client is running under LIMITED cryptographic controls. Consider installing the JCE Unlimited Strength Jurisdiction Policy Files.");

        ColorPrintUtil.printKeyValue("Testing server ", host + ":" + port);

        SecureRandom rand = SecureRandom.getInstance("NativePRNG");

        String reportFormat = "%9s %8s %s%n";
        String errorReportFormat = "%9s %8s %s %s%n";
        ColorPrintUtil.print(String.format(reportFormat, "Supported", "Protocol", "Cipher"), ColorPrintUtil.COLOR_GREEN_BOLD);

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
            ColorPrintUtil.printErrln("This client supports none of the requested protocols: "
                    + Arrays.asList(sslEnabledProtocols));
            ColorPrintUtil.printErrln("Exiting.");
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
        ColorPrintUtil.printKeyValue("Total Execution time:", TimeUtil.formatElapsedTime(System.currentTimeMillis() - startTime));

        executor.shutdown();
    }

    private static void performBasicConnectivityTest(int connectTimeout, int readTimeout, boolean showCerts, int port, String host, InetSocketAddress address, List<String> supportedProtocols, SSLSocketFactory sf) throws IOException {
        SSLSocket socket = null;

        try {
            socket = testEngine.createSSLSocket(address, host, port, connectTimeout, readTimeout, sf);
            socket.startHandshake();

            ColorPrintUtil.print("Given this client's capabilities ("
                    + supportedProtocols
                    + "), the server prefers protocol=");
            ColorPrintUtil.print(socket.getSession().getProtocol());
            ColorPrintUtil.print(", cipher=");
            ColorPrintUtil.print(socket.getSession().getCipherSuite());
            System.out.println();
            if (showCerts) {
                showCertificateDetails(socket);
            }
        } catch (SocketException se) {
            ColorPrintUtil.printErrln("Error during connection handshake for protocols "
                    + supportedProtocols
                    + ": server likely does not support any of these protocols.");

            if (showCerts)
                ColorPrintUtil.printErrln("Unable to show server certificate without a successful handshake.");
        } catch (CertificateParsingException e) {
            ColorPrintUtil.printErrln("Unable to get the certificate details:" + e.getLocalizedMessage());
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
        ColorPrintUtil.println("Attempting to check certificate:");
        for (Certificate cert : socket.getSession().getPeerCertificates()) {
            String certType = cert.getType();
            ColorPrintUtil.printKeyValue("Certificate: ",  certType);
            if ("X.509".equals(certType)) {
                X509Certificate x509 = (X509Certificate) cert;
                ColorPrintUtil.printKeyValue("Subject    : ",  x509.getSubjectDN().toString());
                ColorPrintUtil.printKeyValue("Issuer     : ",  x509.getIssuerDN().toString());
                ColorPrintUtil.printKeyValue("Serial     : ",  x509.getSerialNumber().toString());
                ColorPrintUtil.printKeyValue("Not Before : ",  DATA_FORMAT.format(x509.getNotBefore()));
                ColorPrintUtil.printKeyValue("Not After  : ",  DATA_FORMAT.format(x509.getNotAfter()));
                try {
                    x509.checkValidity();
                    ColorPrintUtil.println("Certificate is currently valid.");
                } catch (CertificateException ce) {
                    ColorPrintUtil.printErrln("WARNING: certificate is not valid: " + ce.getMessage());
                }
//               ColorPrintUtil.printKeyValue("Signature: ", testEngine.toHexString(x509.getSignature()));
//               ColorPrintUtil.printKeyValue("cert bytes: ",  testEngine.toHexString(cert.getEncoded()));
//               ColorPrintUtil.printKeyValue("cert bytes: ",  cert.getPublicKey());
                ColorPrintUtil.printKeyValue("Alternate Names: ", getAlternativeNames(x509.getSubjectAlternativeNames()));
            } else {
                ColorPrintUtil.printKeyValue("Unknown certificate type (" + cert.getType() + "): " ,  cert.toString());
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

    private static synchronized void cipherProbe(CipherConfig params) {
        List<CipherResponse> responses = testEngine.invoke(params, executor);

        //Print them
        responses.stream()
                .forEach(response -> {
                    if (null != response.getError())
                        ColorPrintUtil.print(String.format(params.getErrorReportFormat(),
                                response.getStatus(),
                                response.getProtocol(),
                                response.getName(),
                                response.getError()), ColorPrintUtil.COLOR_BLUE);
                    else if (!params.isHideRejects() || !"Rejected".equals(response.getStatus()))
                        ColorPrintUtil.print(String.format(params.getReportFormat(),
                                response.getStatus(),
                                response.getProtocol(),
                                response.getName()), ColorPrintUtil.COLOR_BLUE);
                });
    }


}