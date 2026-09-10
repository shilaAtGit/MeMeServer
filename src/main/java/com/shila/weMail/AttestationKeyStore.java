package com.shila.weMail;

import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * App Attest 密钥存储
 *
 * key = userPath（临时路径，每次登录变化）
 * 不存储 userID，保护用户隐私
 */
public class AttestationKeyStore {

    public static class KeyRecord {
        public final String keyId;
        public final PublicKey publicKey;
        public final AtomicInteger counter;
        public final long createdAt;
        public long lastUsedAt;

        public KeyRecord(String keyId, PublicKey publicKey) {
            this.keyId = keyId;
            this.publicKey = publicKey;
            this.counter = new AtomicInteger(0);
            this.createdAt = System.currentTimeMillis();
            this.lastUsedAt = this.createdAt;
        }

        public boolean verifyAndIncrementCounter(int newCounter) {
            int current = counter.get();
            if (newCounter <= current) {
                System.out.println("❌ Counter 无效: current=" + current + ", new=" + newCounter);
                return false;
            }
            counter.set(newCounter);
            lastUsedAt = System.currentTimeMillis();
            return true;
        }
    }

    // ✅ 修改：key = userPath（不再是 userID）
    private static final ConcurrentHashMap<String, KeyRecord> store = new ConcurrentHashMap<>();

    // ✅ 可选：keyId -> userPath 快速索引（但也可以不用，直接遍历）
//    private static final ConcurrentHashMap<String, String> keyIdToUserPath = new ConcurrentHashMap<>();

    // ===== 核心方法 =====

    public static void put(String keyId, PublicKey publicKey) {
        KeyRecord existing = store.get(keyId);
        if (existing != null) {
            System.out.println("⚠️ 公钥已存在，跳过存储: keyId=" + keyId);
            System.out.println("📊 当前存储数: " + store.size());
            return;
        }
        KeyRecord record = new KeyRecord(keyId, publicKey);
        store.put(keyId, record);
        System.out.println("✅ 公钥已存储: keyId=" + keyId);
        System.out.println("📦 存储的公钥 (Base64): " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        System.out.println("📊 当前存储数: " + store.size());
    }
    /**
     * ✅ 通过 userPath 获取公钥（主查询方式）
     */
    public static PublicKey getPublicKeyByUserPath(String userPath) {
        KeyRecord record = store.get(userPath);
        return record != null ? record.publicKey : null;
    }

    /**
     * ✅ 通过 userPath 获取完整 KeyRecord
     */
    public static KeyRecord getByUserPath(String userPath) {
        return store.get(userPath);
    }

    /**
     * ✅ 通过 keyId 获取公钥（备用查询方式）
     */
    public static PublicKey getPublicKeyByKeyId(String keyId) {
        KeyRecord record = store.get(keyId);
        return record != null ? record.publicKey : null;
    }

    /**
     * ✅ 通过 keyId 获取完整 KeyRecord
     */
    public static KeyRecord getByKeyId(String keyId) {
        return store.get(keyId);
    }

    /**
     * ✅ 检查用户是否已认证（通过 userPath）
     */
    public static boolean hasUserPath(String userPath) {
        return store.containsKey(userPath);
    }

    /**
     * ✅ 移除用户（登出时调用）
     */
    public static void removeByUserPath(String userPath) {
        // 注意：此方法保留用于登出时清理，但实际不删除证书
        // 只打印日志，不执行删除
        System.out.println("⚠️ removeByUserPath 已禁用（登出不清理证书），userPath=" + userPath);
        System.out.println("📊 当前存储数: " + store.size());
    }

    /**
     * 验证并递增 counter（通过 userPath）
     */
    public static boolean verifyAndIncrementCounterByUserPath(String userPath, int newCounter) {
        KeyRecord record = store.get(userPath);
        if (record == null) {
            System.out.println("❌ 未找到记录: userPath=" + userPath);
            return false;
        }
        return record.verifyAndIncrementCounter(newCounter);
    }

    public static int size() {
        return store.size();
    }

    public static void clear() {
        store.clear();
//        keyIdToUserPath.clear();
        System.out.println("🗑️ 所有密钥已清空");
    }
}