package com.shila.weMail;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

/**
 * App Attest 挑战值缓存
 *
 * 生成和验证一次性挑战值（Nonce）
 * 纯内存存储，服务器重启后清空
 */
public class AttestationChallengeCache {

    private static final ConcurrentHashMap<String, ChallengeRecord> cache = new ConcurrentHashMap<>();
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * 挑战值记录
     */
    private static class ChallengeRecord {
        final String challenge;
        final long createdAt;

        ChallengeRecord(String challenge) {
            this.challenge = challenge;
            this.createdAt = System.currentTimeMillis();
        }

        boolean isValid() {
            return System.currentTimeMillis() - createdAt < AttestationConstants.CHALLENGE_TIMEOUT_MS;
        }
    }

    /**
     * 生成新的挑战值
     * @return Base64 编码的 32 字节随机数
     */
    public static String generateChallenge() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String challenge = Base64.getEncoder().encodeToString(bytes);
        cache.put(challenge, new ChallengeRecord(challenge));
        System.out.println("📝 Challenge 生成: " + challenge.substring(0, 16) + "...");
        return challenge;
    }

    /**
     * 验证并消耗挑战值
     * @param challenge Base64 编码的挑战值
     * @return true 表示有效且未被使用
     */
    public static boolean validateAndConsume(String challenge) {
        ChallengeRecord record = cache.remove(challenge);
        if (record == null) {
            System.out.println("❌ Challenge 不存在或已使用: " + challenge.substring(0, 16) + "...");
            return false;
        }
        if (!record.isValid()) {
            System.out.println("❌ Challenge 已过期: " + challenge.substring(0, 16) + "...");
            return false;
        }
        System.out.println("✅ Challenge 验证通过: " + challenge.substring(0, 16) + "...");
        return true;
    }

    /**
     * 清理过期挑战值（可定期调用）
     */
    public static void cleanExpired() {
        long now = System.currentTimeMillis();
        cache.entrySet().removeIf(entry ->
                now - entry.getValue().createdAt >= AttestationConstants.CHALLENGE_TIMEOUT_MS
        );
    }
}