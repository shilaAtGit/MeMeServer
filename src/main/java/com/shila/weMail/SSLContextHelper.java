package com.shila.weMail;

import javax.net.ssl.*;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

public class SSLContextHelper {

    public static SSLContext createSSLContext() throws Exception {
        String keystorePath = System.getProperty("ssl.keystore.path", "keystore.jks");
        String password = System.getProperty("ssl.keystore.password");
        if (password == null || password.isEmpty()) {
            throw new IllegalStateException(
                    "必须通过 -Dssl.keystore.password=xxx 指定 keystore 密码"
            );
        }

        try (InputStream keyStoreStream = new FileInputStream(keystorePath)) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreStream, password.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm()
            );
            kmf.init(keyStore, password.toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);
            return sslContext;
        }
    }
}