package com.shila.weMail;

import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;


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

    private static final ConcurrentHashMap<String, KeyRecord> store = new ConcurrentHashMap<>();



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

    public static PublicKey getPublicKeyByUserPath(String userPath) {
        KeyRecord record = store.get(userPath);
        return record != null ? record.publicKey : null;
    }

    public static KeyRecord getByUserPath(String userPath) {
        return store.get(userPath);
    }


    public static PublicKey getPublicKeyByKeyId(String keyId) {
        KeyRecord record = store.get(keyId);
        return record != null ? record.publicKey : null;
    }


    public static KeyRecord getByKeyId(String keyId) {
        return store.get(keyId);
    }


    public static boolean hasUserPath(String userPath) {
        return store.containsKey(userPath);
    }


    public static void removeByUserPath(String userPath) {
        // 注意：此方法保留用于登出时清理，但实际不删除证书
        System.out.println("⚠️ removeByUserPath 已禁用（登出不清理证书），userPath=" + userPath);
        System.out.println("📊 当前存储数: " + store.size());
    }


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
        System.out.println("🗑️ 所有密钥已清空");
    }
}