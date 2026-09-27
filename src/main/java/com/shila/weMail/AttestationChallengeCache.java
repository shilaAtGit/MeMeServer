package com.shila.weMail;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;


public class AttestationChallengeCache {

    private static final ConcurrentHashMap<String, ChallengeRecord> cache = new ConcurrentHashMap<>();
    private static final SecureRandom secureRandom = new SecureRandom();


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


    public static String generateChallenge() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String challenge = Base64.getEncoder().encodeToString(bytes);
        cache.put(challenge, new ChallengeRecord(challenge));
        Log.d("📝 Challenge 生成: " + challenge.substring(0, 16) + "...");
        return challenge;
    }


    public static boolean validateAndConsume(String challenge) {
        ChallengeRecord record = cache.remove(challenge);
        if (record == null) {
            Log.d("❌ Challenge 不存在或已使用: " + challenge.substring(0, 16) + "...");
            return false;
        }
        if (!record.isValid()) {
            Log.d("❌ Challenge 已过期: " + challenge.substring(0, 16) + "...");
            return false;
        }
        Log.d("✅ Challenge 验证通过: " + challenge.substring(0, 16) + "...");
        return true;
    }

    public static void cleanExpired() {
        long now = System.currentTimeMillis();
        cache.entrySet().removeIf(entry ->
                now - entry.getValue().createdAt >= AttestationConstants.CHALLENGE_TIMEOUT_MS
        );
    }
}