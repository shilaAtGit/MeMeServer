package com.shila.weMail;

import javax.net.ssl.*;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;

public class SSLContextHelper {

    public static SSLContext createSSLContext() throws Exception {
        String password = System.getProperty("ssl.keystore.password", "password");

        InputStream keyStoreStream = SSLContextHelper.class.getResourceAsStream("/keystore.jks");
        if (keyStoreStream == null) {
            throw new FileNotFoundException("Keystore not found in resources");
        }

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(keyStoreStream, password.toCharArray());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, password.toCharArray());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);
        return sslContext;
    }
}