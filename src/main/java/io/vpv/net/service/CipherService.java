package io.vpv.net.service;

import io.vpv.net.model.CipherConfig;
import io.vpv.net.model.CipherResponse;
import io.vpv.net.util.SSLUtils;
import sun.security.validator.ValidatorException;

import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * Created by vprasanna on 4/3/18.
 */
public class CipherService {
    /**
     * The executor.
     */
    private static final ExecutorService executor = Executors
            .newFixedThreadPool(10);
    public SSLSocket createSSLSocket(InetSocketAddress address,
                                             String host,
                                             int port,
                                             int readTimeout,
                                             int connectTimeout,
                                             SSLSocketFactory sf)
            throws IOException {
        //
        // Note: SSLSocketFactory has several create() methods.
        // Those that take arguments all connect immediately
        // and have no options for specifying a connection timeout.
        //
        // So, we have to create a socket and connect it (with a
        // connection timeout), then have the SSLSocketFactory wrap
        // the already-connected socket.
        //
        Socket sock = new Socket();
        sock.setSoTimeout(readTimeout);
        sock.connect(address, connectTimeout);

        // Wrap plain socket in an SSL socket
        return (SSLSocket) sf.createSocket(sock, host, port, true);
    }

    public String[] getJVMSupportedCipherSuites(String protocol, SecureRandom rand)
            throws NoSuchAlgorithmException, KeyManagementException {
        SSLContext sc = SSLContext.getInstance(protocol);

        sc.init(null, null, rand);

        return sc.getSocketFactory().getSupportedCipherSuites();
    }

    static final char[] hexChars = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'a', 'b', 'c', 'd', 'e', 'f'};

    public String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);

        for (byte b : bytes)
            sb.append(hexChars[(b >> 4) & 0x0f])
                    .append(hexChars[b & 0x0f]);

        return sb.toString();
    }

    public List<CipherResponse> invoke(CipherConfig params) {
        String[] sslEnabledProtocols = params.getSslEnabledProtocols();
        List<String> supportedProtocols = params.getSupportedProtocols();
        Set<String> cipherSuites = params.getCipherSuites();
        SecureRandom rand = params.getRand();
        String[] sslCipherSuites = params.getSslCipherSuites();
        KeyManager[] keyManagers = params.getKeyManagers();
        TrustManager[] trustManagers = params.getTrustManagers();
        boolean showHandshakeErrors = params.isShowHandshakeErrors();
        boolean stop = params.isStop();
        boolean showSSLErrors = params.isShowSSLErrors();
        boolean showErrors = params.isShowErrors();
        boolean hideRejects = params.isHideRejects();
        String reportFormat = params.getReportFormat();
        String errorReportFormat = params.getErrorReportFormat();

        List<CipherResponse> responses = new ArrayList<>();
        List<CompletableFuture<CipherResponse>> futureResponses = new ArrayList<>();
        for (int i = 0; i < sslEnabledProtocols.length && !params.isStop(); ++i) {
            String protocol = sslEnabledProtocols[i];

            String[] supportedCipherSuites = null;

            try {
                supportedCipherSuites = getJVMSupportedCipherSuites(protocol, rand);
            } catch (NoSuchAlgorithmException nsae) {
                System.out.print(String.format(params.getReportFormat(), "-----", protocol, " Not supported by client"));
                supportedProtocols.remove(protocol);
                continue;
            } catch (Exception e) {
                e.printStackTrace();
                continue; // Skip this protocol
            }

            // Restrict cipher suites to those specified by sslCipherSuites
            cipherSuites.clear();
            cipherSuites.addAll(Arrays.asList(supportedCipherSuites));

            if (null != sslCipherSuites)
                cipherSuites.retainAll(Arrays.asList(sslCipherSuites));

            if (cipherSuites.isEmpty()) {
                System.err.println("No overlapping cipher suites found for protocol " + protocol);
                supportedProtocols.remove(protocol);
                continue; // Go to the next protocol
            }

            for (String cipherSuite : cipherSuites) {
//                if (stop) {
//                    break;
//                }
                CompletableFuture<CipherResponse> futureResponse = CompletableFuture.supplyAsync(() -> {
                    return performCipherTest(params, rand, keyManagers,
                            trustManagers, showHandshakeErrors,
                            stop, showSSLErrors, showErrors,
                            hideRejects, reportFormat, errorReportFormat,
                            protocol, cipherSuite);
                }, executor);
                if (null != futureResponse) {
                    futureResponses.add(futureResponse);
                }
            }
        }
//        CompletableFuture.allOf(futureResponses.toArray( new CompletableFuture[futureResponses.size()])).join();
//
//
//        futureResponses.stream()
//                .forEach(response -> {
//                            try {
//                                responses.add(response.get());
//                            } catch (ExecutionException | InterruptedException e) {
//                                System.out.println("Problem while accessing network:" + e.getMessage());
//                            }
//                        }
//                );
        responses = futureResponses.stream()
                .map(CompletableFuture::join)
                .collect(Collectors.toList());
        executor.shutdown();
        return responses;
    }

    private CipherResponse performCipherTest(CipherConfig params, SecureRandom rand, KeyManager[] keyManagers, TrustManager[] trustManagers, boolean showHandshakeErrors, boolean stop, boolean showSSLErrors, boolean showErrors, boolean hideRejects, String reportFormat, String errorReportFormat, String protocol, String cipherSuite) {
                    String status;

                    SSLSocketFactory sf = null;
                    try {
                        sf = SSLUtils.getSSLSocketFactory(protocol,
                                new String[]{protocol},
                                new String[]{cipherSuite},
                                rand,
                                trustManagers,
                                keyManagers);
                    } catch (NoSuchAlgorithmException e) {
                        throw new RuntimeException(e);
                    } catch (KeyManagementException e) {
                        throw new RuntimeException(e);
                    }

                    SSLSocket socket = null;
                    String error = null;

                    try {
                        socket = createSSLSocket(params.getAddress(), params.getHost(), params.getPort(), params.getConnectTimeout(), params.getReadTimeout(), sf);

                        socket.startHandshake();



                        SSLSession sess = socket.getSession();
                        //                    Thread.currentThread().sleep(200);System.exit(0);
                        //                    System.err.println("NORMAL SESSION = " + sess);
                        //                    System.err.println("MAIN THREADNAME: " + Thread.currentThread().getName());
                        assert protocol.equals(sess.getProtocol());
                        assert cipherSuite.equals(sess.getCipherSuite());


                        status = "Accepted";
                    } catch (SSLHandshakeException she) {
                        Throwable cause = she.getCause();
                        if (null != cause && cause instanceof ValidatorException) {
                            status = "Untrusted";
                            error = "Server certificate is not trusted. All other connections will fail similarly.";
//                        TODO: Need to add back
//                        stop = true;
                        } else
                            status = "Rejected";

                        if (showHandshakeErrors)
                            error = "SHE: " + she.getLocalizedMessage() + ", type=" + she.getClass().getName() + ", nested=" + she.getCause();
                    } catch (SSLException ssle) {
                        if (showSSLErrors)
                            error = "SE: " + ssle.getLocalizedMessage();

                        status = "Rejected";
                    } catch (SocketTimeoutException ste) {
                        if (showErrors)
                            error = "SocketException" + ste.getLocalizedMessage();

                        status = "Timeout";
                    } catch (SocketException se) {
                        if (showErrors)
                            error = se.getLocalizedMessage();

                        status = "Failed";
                    } catch (IOException ioe) {
                        if (showErrors)
                            error = ioe.getLocalizedMessage();

                        ioe.printStackTrace();
                        status = "Failed";
                    } catch (Exception e) {
                        if (showErrors)
                            error = e.getLocalizedMessage();

                        e.printStackTrace();
                        status = "Failed";
                    } finally {
                        if (null != socket) try {
                            socket.close();
                        } catch (IOException ioe) {
                            ioe.printStackTrace();
                        }
                    }


        return new CipherResponse(cipherSuite, status, protocol, error, stop);


    }
}
