package com.shila.weMail;

import javax.net.ssl.*;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;
/*
use
正在为以下对象生成 2,048 位RSA密钥对和自签名证书 (SHA256withRSA) (有效期为 365 天):
	 CN=shila_1987, OU=personal, O=wePost, L=earth, ST=zelda, C=001

 */
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