package com.shila.weMail;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;


public class AppAttestVerifier {

    static {
        java.security.Security.addProvider(new BouncyCastleProvider());
    }


    public static PublicKey verifyAttestation(
            String attestationBase64,
            String challengeBase64,
            String keyId,
            String userPath) {

        try {
            byte[] attestationBytes = Base64.getDecoder().decode(attestationBase64);
            byte[] challengeBytes = Base64.getDecoder().decode(challengeBase64);

            // 1. 解析 CBOR
            List<DataItem> dataItems = CborDecoder.decode(attestationBytes);
            if (dataItems == null || dataItems.isEmpty()) {
                Log.e("❌ CBOR 数据为空");
                return null;
            }

            DataItem firstItem = dataItems.get(0);
            if (!(firstItem instanceof Map)) {
                Log.e("❌ CBOR 顶层不是 Map 类型");
                return null;
            }
            Map map = (Map) firstItem;

            // 2. 验证 fmt
            DataItem fmtItem = map.get(new UnicodeString("fmt"));
            if (fmtItem == null) {
                Log.e("❌ 缺少 fmt 字段");
                return null;
            }
            String fmt = ((co.nstant.in.cbor.model.UnicodeString) fmtItem).getString();
            if (!"apple-appattest".equals(fmt)) {
                Log.e("❌ 不支持的 fmt: " + fmt);
                return null;
            }

            // 3. 提取 attStmt
            DataItem attStmtItem = map.get(new UnicodeString("attStmt"));
            if (!(attStmtItem instanceof Map)) {
                Log.e("❌ attStmt 不是 Map 类型");
                return null;
            }
            Map attStmt = (Map) attStmtItem;

            // 4. 提取 x5c 证书链
            DataItem x5cItem = attStmt.get(new UnicodeString("x5c"));
            if (!(x5cItem instanceof Array)) {
                Log.e("❌ x5c 不是 Array 类型");
                return null;
            }
            Array x5cArray = (Array) x5cItem;
            List<byte[]> certBytesList = new ArrayList<>();
            for (DataItem certItem : x5cArray.getDataItems()) {
                if (certItem instanceof ByteString) {
                    certBytesList.add(((ByteString) certItem).getBytes());
                }
            }
            if (certBytesList.isEmpty()) {
                Log.e("❌ x5c 证书列表为空");
                return null;
            }

            // 5. 提取 authData
            DataItem authDataItem = map.get(new UnicodeString("authData"));
            if (!(authDataItem instanceof ByteString)) {
                Log.e("❌ authData 不是 ByteString 类型");
                return null;
            }
            byte[] authData = ((ByteString) authDataItem).getBytes();
            Log.d("🔐 authData 长度: " + authData.length);

            // 6. 提取 receipt（用于后续 fraud metric）
            DataItem receiptItem = attStmt.get(new UnicodeString("receipt"));
            byte[] receipt = null;
            if (receiptItem instanceof ByteString) {
                receipt = ((ByteString) receiptItem).getBytes();
            }

            // 7. 验证证书链
            Log.d("🔐 x5c 证书数量: " + certBytesList.size());
            for (int i = 0; i < certBytesList.size(); i++) {
                byte[] certData = certBytesList.get(i);
            }
            X509Certificate[] certChain = verifyCertificateChain(certBytesList);
            if (certChain == null || certChain.length == 0) {
                Log.e("❌ 证书链验证失败");
                return null;
            }
            X509Certificate leafCert = certChain[0];

            // 8. 验证证书 CN 是否匹配 keyId
            String cn = extractCN(leafCert);
            String keyIdHex = keyIdToHex(keyId);
            if (cn == null || keyIdHex == null || !cn.equalsIgnoreCase(keyIdHex)) {
                Log.e("❌ keyId 不匹配");
                return null;
            }

            // 9. 验证 Nonce
            if (!verifyNonce(map, challengeBytes, leafCert)) {
                Log.e("❌ Nonce 验证失败");
                return null;
            }

            // 10. 验证 RP ID (App ID)
            byte[] appIdHash = sha256(AttestationConstants.getAppId().getBytes());
            byte[] rpIdHashFromAuthData = Arrays.copyOfRange(authData, 0, 32);
            if (!Arrays.equals(appIdHash, rpIdHashFromAuthData)) {
                Log.e("❌ RP ID 不匹配");
                return null;
            }

            // 11. 验证 counter = 0（首次 attestation）
            int counter = getCounter(authData);
            if (counter != 0) {
                Log.e("❌ Counter 不为 0: " + counter);
                return null;
            }

            // 12. 验证 AAGUID
            String aaguid = extractAAGUID(authData);
            if (!"appattest".equals(aaguid) && !"appattestsandbox".equals(aaguid)) {
                Log.e("❌ 无效的 AAGUID: " + aaguid);
                return null;
            }
            Log.d("🔐 环境: " + ("appattest".equals(aaguid) ? "production" : "development"));

            // 13. 验证 credential ID 是否匹配 keyId
            byte[] keyIdBytes = Base64.getDecoder().decode(keyId);
            byte[] credentialId = getCredentialId(authData);
            if (!Arrays.equals(keyIdBytes, credentialId)) {
                Log.e("❌ credential ID 不匹配 keyId");
                return null;
            }

            // 14. 提取公钥
            PublicKey publicKey = leafCert.getPublicKey();
            Log.d("✅ Attestation 验证通过");

            return publicKey;

        } catch (Exception e) {
            Log.e("❌ Attestation 验证异常: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }


    public static boolean verifyAssertion(
            String assertionBase64,
            String clientDataHashBase64,
            String identifier,
            PublicKey publicKey) {

        long t0 = System.currentTimeMillis();
        try {
            byte[] assertionBytes = Base64.getDecoder().decode(assertionBase64);
            byte[] clientDataHash = Base64.getDecoder().decode(clientDataHashBase64);

            long t1 = System.currentTimeMillis();

            // 1. 解析 CBOR

            List<DataItem> dataItems = CborDecoder.decode(assertionBytes);
            if (dataItems == null || dataItems.isEmpty()) {
                return false;
            }


            DataItem firstItem = dataItems.get(0);
            if (!(firstItem instanceof Map)) {
                Log.e("❌ [verifyAssertion] 顶层不是 Map 类型");
                return false;
            }
            Map map = (Map) firstItem;

            // 2. 提取 signature
            DataItem signatureItem = map.get(new UnicodeString("signature"));
            if (!(signatureItem instanceof ByteString)) {
                Log.e("❌ [verifyAssertion] signature 不是 ByteString");
                return false;
            }
            byte[] signature = ((ByteString) signatureItem).getBytes();

            long t2 = System.currentTimeMillis();

            // 3. 提取 authenticatorData
            DataItem authDataItem = map.get(new UnicodeString("authenticatorData"));
            if (!(authDataItem instanceof ByteString)) {
                Log.e("❌ [verifyAssertion] authenticatorData 不是 ByteString");
                return false;
            }
            byte[] authenticatorData = ((ByteString) authDataItem).getBytes();

            long t3 = System.currentTimeMillis();

            // 4. 提取 counter
            int counter = getCounter(authenticatorData);

            // 5. 验证 RP ID
            byte[] appIdHash = sha256(AttestationConstants.getAppId().getBytes());
            byte[] rpIdHashFromAuthData = Arrays.copyOfRange(authenticatorData, 0, 32);
            boolean rpIdMatch = Arrays.equals(appIdHash, rpIdHashFromAuthData);
            if (!rpIdMatch) {
                Log.e("❌ [verifyAssertion] RP ID 不匹配");
                return false;
            }

            // 6. 验证签名
            byte[] nonce = sha256(concat(authenticatorData, clientDataHash));


            Signature sig = Signature.getInstance("SHA256withECDSA", "BC");
            sig.initVerify(publicKey);
            sig.update(nonce);

            boolean result = sig.verify(signature);


            if (!result) {
                Log.e("❌ [verifyAssertion] 签名验证失败");
                long tEnd = System.currentTimeMillis();
                Log.d("⏱️ [verifyAssertion] ========== END 总耗时: " + (tEnd - t0) + "ms ==========");
                return false;
            }

            // 7. 验证 counter

            AttestationKeyStore.KeyRecord record = AttestationKeyStore.getByKeyId(identifier);
            if (record != null) {
                if (!record.verifyAndIncrementCounter(counter)) {
                    Log.e("❌ [verifyAssertion] Counter 验证失败");
                    return false;
                }
            } else {
                Log.d("⚠️ [verifyAssertion] 未找到记录，跳过 counter 验证");
            }

            long counterEnd = System.currentTimeMillis();

            long tEnd = System.currentTimeMillis();
            Log.d("✅ [verifyAssertion] 验证通过!");

            return true;

        } catch (Exception e) {
            Log.e("❌ [verifyAssertion] 异常: " + e.getMessage());
            e.printStackTrace();
            long tEnd = System.currentTimeMillis();
            Log.d("⏱️ [verifyAssertion] 总耗时(异常): " + (tEnd - t0) + "ms");
            return false;
        }
    }


    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 不可用", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static int getCounter(byte[] authData) {
        // authData 结构: rpIdHash(32) + flags(1) + counter(4) + ...
        if (authData.length < 37) {
            return -1;
        }
        // ✅ counter 从偏移 33 开始（偏移 32 是 flags）
        return ((authData[33] & 0xFF) << 24) |
                ((authData[34] & 0xFF) << 16) |
                ((authData[35] & 0xFF) << 8) |
                (authData[36] & 0xFF);
    }

    private static byte[] getCredentialId(byte[] authData) {
        // authData 结构: rpIdHash(32) + flags(1) + counter(4) + aaguid(16) + credentialIdLength(2) + credentialId
        if (authData.length < 55) {
            return null;
        }
        int credentialIdLength = ((authData[53] & 0xFF) << 8) | (authData[54] & 0xFF);
        byte[] credentialId = new byte[credentialIdLength];
        System.arraycopy(authData, 55, credentialId, 0, credentialIdLength);
        return credentialId;
    }

    private static String extractAAGUID(byte[] authData) {
        if (authData.length < 48) {
            return "unknown";
        }
        // aaguid 位于 authData 偏移 32 处，16 字节
        byte[] aaguidBytes = new byte[16];
        System.arraycopy(authData, 32, aaguidBytes, 0, 16);
        StringBuilder sb = new StringBuilder();
        for (byte b : aaguidBytes) {
            sb.append(String.format("%02x", b));
        }
        String aaguid = sb.toString();
        if (aaguid.contains("61707061747465737473616e64626f78")) {
            return "appattestsandbox";
        } else if (aaguid.contains("617070617474657374")) {
            return "appattest";
        }
        return aaguid;
    }

    private static boolean verifyNonce(Map map, byte[] challenge, X509Certificate leafCert) {
        try {
            // 从证书中提取 nonce (OID: 1.2.840.113635.100.8.2)
            byte[] nonceFromCert = extractNonceFromCertificate(leafCert);
            if (nonceFromCert == null) {
                Log.e("❌ 无法从证书提取 Nonce");
                return false;
            }

            // 计算 expectedNonce: SHA256(authData || SHA256(challenge))
            DataItem authDataItem = map.get(new UnicodeString("authData"));
            if (!(authDataItem instanceof ByteString)) {
                Log.e("❌ authData 不是 ByteString");
                return false;
            }
            byte[] authData = ((ByteString) authDataItem).getBytes();

            byte[] challengeHash = sha256(challenge);
            byte[] combined = concat(authData, challengeHash);
            byte[] expectedNonce = sha256(combined);

            return Arrays.equals(nonceFromCert, expectedNonce);

        } catch (Exception e) {
            Log.e("❌ Nonce 验证异常: " + e.getMessage());
            return false;
        }
    }

    private static byte[] extractNonceFromCertificate(X509Certificate cert) {
        try {
            // OID: 1.2.840.113635.100.8.2
            byte[] extensionValue = cert.getExtensionValue("1.2.840.113635.100.8.2");
            if (extensionValue == null) {
                return null;
            }

            ASN1Primitive extensionPrimitive = ASN1Primitive.fromByteArray(extensionValue);
            ASN1OctetString outerOctet = ASN1OctetString.getInstance(extensionPrimitive);
            byte[] octets = outerOctet.getOctets();

            ASN1Primitive inner = ASN1Primitive.fromByteArray(octets);

            // 处理 DLSequence（Apple 使用 DLSequence 而不是 ASN1Sequence）
            if (inner instanceof org.bouncycastle.asn1.DLSequence) {
                org.bouncycastle.asn1.DLSequence seq = (org.bouncycastle.asn1.DLSequence) inner;
                // 取第一个元素
                ASN1Primitive first = seq.getObjectAt(0).toASN1Primitive();
                // 如果第一个元素是 DLTaggedObject，提取其内部数据
                if (first instanceof org.bouncycastle.asn1.DLTaggedObject) {
                    org.bouncycastle.asn1.DLTaggedObject tagged = (org.bouncycastle.asn1.DLTaggedObject) first;
                    ASN1Primitive baseObject = tagged.getBaseObject().toASN1Primitive();
                    if (baseObject instanceof ASN1OctetString) {
                        return ((ASN1OctetString) baseObject).getOctets();
                    }
                    // 如果 baseObject 是 ASN1Sequence，取第一个元素
                    if (baseObject instanceof ASN1Sequence) {
                        ASN1Sequence innerSeq = (ASN1Sequence) baseObject;
                        ASN1OctetString nonceOctet = ASN1OctetString.getInstance(innerSeq.getObjectAt(0));
                        return nonceOctet.getOctets();
                    }
                    // 如果 baseObject 是 DLSequence
                    if (baseObject instanceof org.bouncycastle.asn1.DLSequence) {
                        org.bouncycastle.asn1.DLSequence innerDLSeq = (org.bouncycastle.asn1.DLSequence) baseObject;
                        ASN1OctetString nonceOctet = ASN1OctetString.getInstance(innerDLSeq.getObjectAt(0));
                        return nonceOctet.getOctets();
                    }
                }
                // 如果第一个元素直接是 ASN1OctetString
                if (first instanceof ASN1OctetString) {
                    return ((ASN1OctetString) first).getOctets();
                }
            }

            // 兼容标准 ASN1Sequence
            if (inner instanceof ASN1Sequence) {
                ASN1Sequence seq = (ASN1Sequence) inner;
                ASN1Primitive first = seq.getObjectAt(0).toASN1Primitive();
                if (first instanceof ASN1OctetString) {
                    return ((ASN1OctetString) first).getOctets();
                }
                if (first instanceof org.bouncycastle.asn1.DLTaggedObject) {
                    org.bouncycastle.asn1.DLTaggedObject tagged = (org.bouncycastle.asn1.DLTaggedObject) first;
                    ASN1Primitive baseObject = tagged.getBaseObject().toASN1Primitive();
                    if (baseObject instanceof ASN1OctetString) {
                        return ((ASN1OctetString) baseObject).getOctets();
                    }
                }
            }

            // 兼容直接是 DLTaggedObject
            if (inner instanceof org.bouncycastle.asn1.DLTaggedObject) {
                org.bouncycastle.asn1.DLTaggedObject tagged = (org.bouncycastle.asn1.DLTaggedObject) inner;
                ASN1Primitive baseObject = tagged.getBaseObject().toASN1Primitive();
                if (baseObject instanceof ASN1OctetString) {
                    return ((ASN1OctetString) baseObject).getOctets();
                }
            }

            Log.e("❌ 无法解析 Nonce: 未知格式 " + inner.getClass().getName());
            return null;

        } catch (Exception e) {
            Log.e("❌ 提取 Nonce 异常: " + e.getMessage());
            return null;
        }
    }

    private static X509Certificate[] verifyCertificateChain(List<byte[]> certBytesList) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certs = new ArrayList<>();

            for (byte[] certData : certBytesList) {
                ByteArrayInputStream bais = new ByteArrayInputStream(certData);
                X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
                certs.add(cert);
            }

            if (certs.isEmpty()) {
                return null;
            }

            // 加载 Apple 根证书
            byte[] rootCertBytes = Base64.getDecoder().decode(AttestationConstants.APPLE_ROOT_CERT_BASE64);
            X509Certificate rootCert = (X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(rootCertBytes)
            );

            // ✅ 验证完整证书链
            // 证书链顺序: [叶子证书, 中间证书, ...]
            // 验证: 叶子证书 ← 中间证书 ← ... ← 根证书

            // 1. 验证叶子证书的有效性
            X509Certificate leafCert = certs.get(0);
            leafCert.checkValidity();

            // 2. 验证证书链（从叶子到根）
            for (int i = 0; i < certs.size() - 1; i++) {
                X509Certificate cert = certs.get(i);
                X509Certificate issuer = certs.get(i + 1);
                cert.verify(issuer.getPublicKey());
            }

            // 3. 验证最后一个证书由根证书签名
            X509Certificate lastCert = certs.get(certs.size() - 1);
            lastCert.verify(rootCert.getPublicKey());
            return certs.toArray(new X509Certificate[0]);

        } catch (Exception e) {
            Log.e("❌ 证书链验证失败: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private static String extractCN(X509Certificate cert) {
        try {
            String subject = cert.getSubjectX500Principal().getName();
            for (String part : subject.split(",")) {
                String trimmed = part.trim();
                if (trimmed.startsWith("CN=")) {
                    return trimmed.substring(3);
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private static String keyIdToHex(String keyIdBase64) {
        try {
            byte[] keyIdBytes = Base64.getDecoder().decode(keyIdBase64);
            StringBuilder hex = new StringBuilder();
            for (byte b : keyIdBytes) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            Log.e("❌ keyId Base64 解码失败: " + e.getMessage());
            return null;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}