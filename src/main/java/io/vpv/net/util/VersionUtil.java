package io.vpv.net.util;

import java.util.Properties;

public class VersionUtil {
    public static String getVersion() {
        try {
            Properties properties = new Properties();
            properties.load(VersionUtil.class.getClassLoader().getResourceAsStream("application.properties"));
            StringBuilder builder = new StringBuilder();
            builder.append("javassltest").append("\n")
                    .append("Simple Java based CLI Tool to test SSL connection and list the ciphers \n")
                    .append("Version ").append(properties.getProperty("application.version")).append("\n")
                    .append("Build Date ").append(properties.getProperty("application.builtDate")).append("\n")
                    .append("Built JDK ").append(properties.getProperty("application.builtJDK")).append("\n");
            return builder.toString();
        } catch (Exception e) {
            //Ignored as somethimes the version application.properties cannot be found.
        }
        return "UNKNOWN";
    }
}
