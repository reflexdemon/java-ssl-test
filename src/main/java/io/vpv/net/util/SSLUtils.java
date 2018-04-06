package io.vpv.net.util;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Lots of useful SSL-related goodies.
 *
 * @author Christopher Schultz
 * @author Apache Software Foundation (some code adapted/lifted from Apache Tomcat).
 */
public class SSLUtils
{
    private static final Logger log = Logger.getLogger(SSLUtils.class.getName());

    protected static class VerifyAllHostnameVerifier
            implements HostnameVerifier
    {
        @Override
        public boolean verify(String hostname, SSLSession session)
        {
            return true;
        }
    }

    protected static class TrustAllTrustManager
            implements X509TrustManager
    {
        private static final X509Certificate[] EMPTY = new X509Certificate[0];

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return EMPTY;
        }
        @Override
        public void checkClientTrusted(X509Certificate[] certs,
                                       String authType) {
            // Trust all clients
        }
        @Override
        public void checkServerTrusted(X509Certificate[] certs,
                                       String authType) {
            // Trust all servers
        }
    }
    public static void disableSSLHostnameVerification()
    {
        HttpsURLConnection.setDefaultHostnameVerifier(new VerifyAllHostnameVerifier());
    }

    private static final TrustManager[] trustAllCerts = new TrustManager[] {
            new TrustAllTrustManager()
    };

    public static TrustManager[] getTrustAllCertsTrustManagers()
    {
        return trustAllCerts.clone();
    }

    /**
     * Creates an SSLSocketFactory that supports only the specified protocols
     * and ciphers.
     */
    public static SSLSocketFactory getSSLSocketFactory(String protocol,
                                                       String[] sslEnabledProtocols,
                                                       String[] sslCipherSuites,
                                                       SecureRandom random,
                                                       TrustManager[] tms,
                                                       KeyManager[] kms)
            throws NoSuchAlgorithmException, KeyManagementException
    {
        SSLContext sc = SSLContext.getInstance(protocol);

//        ColorPrintUtil.printKeyValue("Wanted protocol: " , protocol);
//        ColorPrintUtil.printKeyValue("Got protocol:    " , sc.getProtocol());

        sc.init(kms, tms, random);

        SSLSocketFactory sf = sc.getSocketFactory();

        if(null != sslEnabledProtocols
                || null != sslCipherSuites)
            sf = new CustomSSLSocketFactory(sf,
                    sslEnabledProtocols,
                    sslCipherSuites);

        return sf;
    }

    /**
     * In order to customize the specific enabled protocols and cipher suites,
     * a customized SSLSocketFactory must be used.
     *
     * This is just a wrapper around that customization.
     */
    public static class CustomSSLSocketFactory
            extends javax.net.ssl.SSLSocketFactory
    {
        private final String[] _sslEnabledProtocols;
        private final String[] _sslCipherSuites;
        private final SSLSocketFactory _base;

        public CustomSSLSocketFactory(SSLSocketFactory base,
                                      String[] sslEnabledProtocols,
                                      String[] sslCipherSuites)
        {
            _base = base;
            if(null == sslEnabledProtocols)
                _sslEnabledProtocols = null;
            else
                _sslEnabledProtocols = sslEnabledProtocols.clone();
            if(null == sslCipherSuites || 0 == sslCipherSuites.length)
                _sslCipherSuites = base.getDefaultCipherSuites();
            else if(1 == sslCipherSuites.length && "ALL".equalsIgnoreCase(sslCipherSuites[0]))
                _sslCipherSuites = base.getSupportedCipherSuites();
            else
                _sslCipherSuites = sslCipherSuites.clone();
        }

        public String[] getDefaultCipherSuites() {
            return _base.getDefaultCipherSuites();
        }
        public String[] getSupportedCipherSuites() {
            return _base.getSupportedCipherSuites();
        }

        private SSLSocket customize(Socket s)
        {
            SSLSocket socket = (SSLSocket)s;

            if(null != _sslEnabledProtocols)
                socket.setEnabledProtocols(_sslEnabledProtocols);

            socket.setEnabledCipherSuites(_sslCipherSuites);

            return socket;
        }

        @Override
        public Socket createSocket(Socket s,
                                   String host,
                                   int port,
                                   boolean autoClose)
                throws IOException
        {
            return customize(_base.createSocket(s, host, port, autoClose));
        }
        @Override
        public Socket createSocket(String host, int port)
                throws IOException
        {
            return customize(_base.createSocket(host, port));
        }
        @Override
        public Socket createSocket(InetAddress host, int port)
                throws IOException
        {
            return customize(_base.createSocket(host, port));
        }
        @Override
        public Socket createSocket(String host, int port,
                                   InetAddress localHost, int localPort)
                throws IOException
        {
            return customize(_base.createSocket(host, port, localHost, localPort));
        }
        @Override
        public Socket createSocket(InetAddress address, int port,
                                   InetAddress localAddress, int localPort)
                throws IOException
        {
            return customize(_base.createSocket(address, port, localAddress, localPort));
        }
    }

    //
    // All the code for loading TrustManagers was adapted from code in
    // the Apache Tomcat project.
    //

    /**
     * Gets an array of TrustManagers for the specified trust store
     * and optional CRL file.
     *
     * @param trustStoreFilename
     * @param trustStorePassword
     * @param trustStoreType
     * @param trustStoreProvider
     * @param trustStoreAlgorithm
     * @param maxCertificatePathLength
     * @param crlFilename
     *
     * @return An array of TrustManagers
     *
     * @throws IOException
     * @throws KeyStoreException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws InvalidAlgorithmParameterException
     * @throws CRLException
     */
    public static TrustManager[] getTrustManagers(String trustStoreFilename,
                                                     String trustStorePassword,
                                                     String trustStoreType,
                                                     String trustStoreProvider,
                                                     String trustStoreAlgorithm,
                                                     Integer maxCertificatePathLength,
                                                     String crlFilename)
            throws IOException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, InvalidAlgorithmParameterException, CRLException
    {
        KeyStore trustStore = getStore(trustStoreFilename,
                trustStorePassword,
                trustStoreType,
                trustStoreProvider);

        if(null == trustStoreAlgorithm)
            trustStoreAlgorithm = TrustManagerFactory.getDefaultAlgorithm();

        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(trustStoreAlgorithm);
        if (null == crlFilename)
        {
            tmf.init(trustStore);
        }
        else
        {
            CertPathParameters params =
                    getParameters(trustStoreAlgorithm,
                            crlFilename,
                            maxCertificatePathLength,
                            trustStore);

            ManagerFactoryParameters mfp =
                    new CertPathTrustManagerParameters(params);

            tmf.init(mfp);
        }

        return tmf.getTrustManagers();
    }

    /**
     * Return the initialization parameters for the TrustManager.
     * Currently, only the default <code>PKIX</code> is supported.
     *
     * @param algorithm The algorithm to get parameters for.
     * @param crlFilename The path to the CRL file.
     * @param maxCertificateChainLength Optional maximum cert chain length.
     * @param trustStore The configured TrustStore.
     *
     * @return The parameters including the TrustStore and any CRLs.
     *
     * @throws InvalidAlgorithmParameterException
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws CRLException
     * @throws NoSuchAlgorithmException
     */
    protected static CertPathParameters getParameters(String algorithm,
                                                      String crlFilename,
                                                      Integer maxCertificateChainLength,
                                                      KeyStore trustStore)
            throws KeyStoreException, InvalidAlgorithmParameterException, CRLException, CertificateException, IOException, NoSuchAlgorithmException
    {
        CertPathParameters params = null;
        if("PKIX".equalsIgnoreCase(algorithm)) {
            PKIXBuilderParameters xparams =
                    new PKIXBuilderParameters(trustStore, new X509CertSelector());
            Collection<? extends CRL> crls = getCRLs(crlFilename);
            CertStoreParameters csp = new CollectionCertStoreParameters(crls);
            CertStore store = CertStore.getInstance("Collection", csp);
            xparams.addCertStore(store);
            xparams.setRevocationEnabled(true);

            if(maxCertificateChainLength != null)
                xparams.setMaxPathLength(maxCertificateChainLength.intValue());

            params = xparams;
        } else {
            throw new CRLException("CRLs not supported for type: " + algorithm);
        }
        return params;
    }

    /**
     * Loads a collection of Certificate Revocation Lists (CRLs)
     * from a file.
     *
     * @param crlFilename The file name of the CRL.
     *
     * @return A Collection of CRLs from the specified file.
     *
     * @throws IOException If the CRL file could not be loaded.
     * @throws CRLException If the CRL list cannot be loaded.
     * @throws CertificateException If there is a problem with one
     *         of the certificates in the revocation list.
     */
    public static Collection<? extends CRL> getCRLs(String crlFilename)
            throws IOException, CRLException, CertificateException
    {
        File crlFile = new File(crlFilename);

        Collection<? extends CRL> crls = null;
        InputStream is = null;
        try
        {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            is = new FileInputStream(crlFile);
            crls = cf.generateCRLs(is);
        }
        finally
        {
            if(is != null) try{ is.close(); }
            catch(IOException ioe) { log.log(Level.SEVERE, "Cannot close CRL file", ioe); }
        }
        return crls;
    }

    /**
     * Loads a keystore.
     *
     * @param storeFilename The file name of the keystore.
     * @param storePassword The keystore password.
     * @param storeType The type of the keystore.
     * @param storeProvider Optional keystore provider.
     *
     * @return A KeyStore loaded from the specified file.
     *
     * @throws IOException If the file cannot be read.
     * @throws KeyStoreException If the KeyStore cannot be read.
     * @throws NoSuchProviderException If the provider is not recognized.
     * @throws NoSuchAlgorithmException If the an algorithm used by the KeyStore is no recognized.
     * @throws CertificateException If there is a problem with a certificate in the KeyStore.
     */
    public static KeyStore getStore(String storeFilename,
                                    String storePassword,
                                    String storeType,
                                    String storeProvider)
            throws IOException, KeyStoreException, NoSuchProviderException, CertificateException, NoSuchAlgorithmException
    {
        KeyStore ks = null;
        InputStream in = null;

        try
        {
            if(null == storeProvider)
                ks = KeyStore.getInstance(storeType);
            else
                ks = KeyStore.getInstance(storeType, storeProvider);

            in = new FileInputStream(storeFilename);

            char[] storePass = null;
            if (storePassword != null && !"".equals(storePassword))
                storePass = storePassword.toCharArray();

            ks.load(in, storePass);

            return ks;
        }
        finally
        {
            if(null != in) try { in.close(); }
            catch (IOException ioe) { log.log(Level.SEVERE, "Cannot close store file", ioe); }
        }
    }
}