package com.migratorydata.authorization.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

public class Configuration {
    public static final String RENEW_TOKEN_BEFORE_SECONDS = "renewTokenBeforeSeconds";
    public static final String SIGNATURE_TYPE = "signature.type";
    public static final String SIGNATURE_HMAC_SECRET = "signature.hmac.secret";
    public static final String SIGNATURE_RSA_PUBLIC_KEY_PATH = "signature.rsa.publicKeyPath";

    private final Properties properties;

    private Configuration() {
        properties = loadConfiguration();
    }

    private final static Configuration config = new Configuration();

    public static Configuration getConfiguration() {
        return config;
    }

    private static Properties loadConfiguration() {
        Properties props = readPropertiesFile("./addons/authorization-jwt/configuration.properties");
        if (props == null) {
            props = readPropertiesFile("/etc/migratorydata/addons/authorization-jwt/configuration.properties");
        }
        if (props == null) {
            props = new Properties();
        }
        if (System.getProperties().containsKey(RENEW_TOKEN_BEFORE_SECONDS)) {
            props.put(RENEW_TOKEN_BEFORE_SECONDS, System.getProperty(RENEW_TOKEN_BEFORE_SECONDS, "60"));
        }
        if (System.getProperties().containsKey(SIGNATURE_TYPE)) {
            props.put(SIGNATURE_TYPE, System.getProperty(SIGNATURE_TYPE, "hmac"));
        }
        if (System.getProperties().containsKey(SIGNATURE_HMAC_SECRET)) {
            props.put(SIGNATURE_HMAC_SECRET, System.getProperty(SIGNATURE_HMAC_SECRET, "He39zDQW7RdkOcxe3L9qvoSQ/ef40BG6Ro4hrHDjE+U="));
        }
        if (System.getProperties().containsKey(SIGNATURE_RSA_PUBLIC_KEY_PATH)) {
            props.put(SIGNATURE_RSA_PUBLIC_KEY_PATH, System.getProperty(SIGNATURE_RSA_PUBLIC_KEY_PATH));
        }

        return props;
    }

    private static Properties readPropertiesFile(String fileName) {
        Properties props = new Properties();
        try (InputStream input = new FileInputStream(fileName)){
            props.load(input);
        } catch (IOException e) {
            return null;
        }
        return props;
    }

    public int getMillisBeforeRenewal() {
        return Integer.parseInt(properties.getProperty(RENEW_TOKEN_BEFORE_SECONDS)) * 1000;
    }

    public String getSignatureType() {
        return properties.getProperty(SIGNATURE_TYPE);
    }

    public String getHMACSecretKey() {
        return properties.getProperty(SIGNATURE_HMAC_SECRET);
    }

    public PublicKey getRSAPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        String key = new String(Files.readAllBytes(new File(properties.getProperty(SIGNATURE_RSA_PUBLIC_KEY_PATH)).toPath()), Charset.defaultCharset());

        String publicKeyPEM = key.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\r", "")
                .replaceAll("\n", "");

        byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
    }
}
