package io.vpv.net;

public class SSLTestTest {

    @org.junit.Test
    public void mainWithNoRejects() {
        String[] argv = {
                "-hiderejects",
                "www.google.com",
        };
        try {
            SSLTest.main(argv);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}