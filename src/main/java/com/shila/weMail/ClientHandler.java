package com.shila.weMail;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.*;
import org.json.*;

/** 说明：
 * 1、热荐对服务器代码进行自创、二创，比如引入netty等
 * 2、核心思想就是服务器“不知、不管”，一切信息、逻辑都在用户手机里
 * 3、公共服务（器）容量有限，热荐搭建私人专属服务器，直接从本项目下载jar包后部署即可
 * 4、私人服务器需要调整的参数包括：
 *    POINT_FEATURE_ENABLED 建议为false
 *    ATTEST_ENABLED 建议为false
 *
 * */
public class ClientHandler implements Runnable {
    /** Attest 功能开关 */
    private static final boolean ATTEST_ENABLED = false;
    // ===== 积分功能配置 =====
    /** 积分功能开关（默认启用） */
    private static final boolean POINT_FEATURE_ENABLED = true;
    /** 登录奖励积分（默认100） */
    private static final int LOGIN_BONUS_POINTS = 100;
    /** 消息最大长度 */
    private static final int MAX_MESSAGE_LENGTH = 2 * 1024 * 1024;
    /** 这是啥 */
    private static final int MAX_FRAME_LENGTH = MAX_MESSAGE_LENGTH + 20;
    private final SSLSocket clientSocket;
    private final ConcurrentMap<String, String> idPathPool;
    private final ConcurrentMap<String, SSLSocket> socketPool;
    private final ConcurrentMap<Integer, SSLSocket> portSocketMap;  // 清理专用
    private final BlockingQueue<String> messageQueue = new LinkedBlockingQueue<>();
    private PrintWriter writer;
    private final AtomicInteger pendingWrites = new AtomicInteger(0);
    private static final int FLUSH_THRESHOLD = 10;
    private static final long FLUSH_INTERVAL_MS = 100;
    private static final int BUFFER_SIZE = 16 * 1024;
    private volatile long lastFlushTime = System.currentTimeMillis();
    private static final ExecutorService forwardExecutor =
            Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "Forward-Thread");
                t.setDaemon(true);
                return t;
            });



    private static final AtomicLong messageIdGenerator = new AtomicLong(0);

    public ClientHandler(SSLSocket socket,
                         ConcurrentMap<String, String> idPathPool,
                         ConcurrentMap<String, SSLSocket> socketPool ,
                        ConcurrentMap<Integer, SSLSocket> portSocketMap) {  // 新增参数
        this.clientSocket = socket;
        this.idPathPool = idPathPool;
        this.socketPool = socketPool;
        this.portSocketMap = portSocketMap;
    }

    private String generateMessageId() {
        return String.format("%d-%d", System.currentTimeMillis(), messageIdGenerator.incrementAndGet());
    }




    @Override
    public void run() {
        String clientAddr = clientSocket.getInetAddress().getHostAddress() + ":" + clientSocket.getPort();
        Log.d("[DIAG] RUN_START client=" + clientAddr);
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(clientSocket.getInputStream()));
             PrintWriter writer = new PrintWriter(
                     new BufferedWriter(
                             new OutputStreamWriter(clientSocket.getOutputStream(), StandardCharsets.UTF_8),
                             BUFFER_SIZE
                     ),
                     false)){

            this.writer = writer;

            final Thread receiverThread = new Thread(() -> {
                try {
                    StringBuilder buffer = new StringBuilder();
                    char[] charBuffer = new char[8192];
                    int charsRead;

                    while (!Thread.currentThread().isInterrupted() &&
                            (charsRead = reader.read(charBuffer)) != -1) {
                        if (buffer.length() + charsRead > MAX_FRAME_LENGTH) {
                            sendErrorResponse("Message too large");
                            cleanup();
                            break;
                        }

                        buffer.append(charBuffer, 0, charsRead);

                        int delimPos;
                        while ((delimPos = buffer.indexOf("\n")) != -1) {
                            String framedMessage = buffer.substring(0, delimPos);
                            buffer.delete(0, delimPos + 1);

                            if (framedMessage.length() > MAX_FRAME_LENGTH) {
                                sendErrorResponse("Frame too large");
                                cleanup();
                                break;
                            }

                            String[] parts = framedMessage.split(":", 2);
                            if (parts.length == 2) {
                                try {
                                    int expectedLength = Integer.parseInt(parts[0]);
                                    String encoded = parts[1];
                                    if (expectedLength > MAX_MESSAGE_LENGTH) {
                                        sendErrorResponse("Declared message length exceeds limit");
                                        continue;
                                    }

                                    if (encoded.length() == expectedLength) {
                                        try {
                                            byte[] decoded = Base64.getDecoder().decode(encoded);
                                            if (decoded.length > MAX_MESSAGE_LENGTH) {
                                                sendErrorResponse("Decoded message exceeds size limit");
                                                continue;
                                            }

                                            String decodedMessage = new String(decoded, StandardCharsets.UTF_8);
                                            messageQueue.put(decodedMessage);
                                        } catch (IllegalArgumentException e) {
                                            sendErrorResponse("Invalid Base64 encoding: " + e.getMessage());
                                        }
                                    } else {
                                        sendErrorResponse("Message length mismatch");
                                    }
                                } catch (NumberFormatException e) {
                                    sendErrorResponse("Invalid length prefix");
                                }
                            } else {
                                sendErrorResponse("Invalid message format");
                            }
                        }
                    }
                } catch (Exception e) {
                    if (!Thread.currentThread().isInterrupted()) {
                        sendErrorResponse("ERROR: " + e.getMessage());
                        cleanup();
                    }
                }
            });
            receiverThread.start();

            while (!Thread.currentThread().isInterrupted()) {
                try {
                    String message = messageQueue.poll(1, TimeUnit.SECONDS);
                    if (message != null) {
                        processMessage(message);
                    }

                    if (!isSocketValid(clientSocket)) {
                        Log.d("[DIAG] RUN_EXIT socket_invalid client=" + clientAddr + " path=" + findPathBySocket(clientSocket));
                        break;
                    }
                } catch (InterruptedException e) {
                    Log.d("[DIAG] RUN_EXIT interrupted client=" + clientAddr);
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    Log.d("[DIAG] RUN_EXIT exception client=" + clientAddr + " msg=" + e.getMessage());
                    break;
                }
            }

            receiverThread.interrupt();
            try {
                receiverThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        } catch (Exception e) {
            Log.d("[DIAG] RUN_EXIT outer_exception client=" + clientAddr + " msg=" + e.getMessage());
        } finally {
            Log.d("[DIAG] RUN_FINALLY client=" + clientAddr + " calling cleanup");
            cleanup();
        }
    }


    private void processMessage(String message) {
        if (message.isEmpty() || message.length() > MAX_MESSAGE_LENGTH) {
            sendErrorResponse("Invalid message length");
            return;
        }
        try {
            if (message.trim().startsWith("{") && message.trim().endsWith("}")) {
                JSONObject json = new JSONObject(message);

                String transTP = json.optString("transTP", "");

                if ("20".equals(transTP)) {
                    handleChallenge(json);
                    return;
                }

                if ("21".equals(transTP)) {
                    handleAttestation(json);
                    return;
                }

                if ("15".equals(transTP)) {
                    handleCheckCertificate(json);
                    return;
                }
                if ("02".equals(transTP) || "03".equals(transTP) || "04".equals(transTP) ||
                        "06".equals(transTP) || "09".equals(transTP)) {
                    if (ATTEST_ENABLED && !verifyBusinessRequest(json, message)) {
                        sendErrorResponse("App attestation verification failed");
                        return;
                    }
                }
                if ("16".equals(transTP)) {
                    handleCleanSocketOnly(json);
                    return;
                }

                handleJsonMessage(json, message);
            } else {
                sendErrorResponse("Invalid message format - expected JSON");
            }
        } catch (JSONException e) {
            sendErrorResponse("Invalid JSON format: " + e.getMessage());
        } catch (Exception e) {
            sendErrorResponse("Internal server error");
        }
    }

    private void handleChallenge(JSONObject json) throws JSONException {
        Log.d("📝 收到挑战请求");

        if (!ATTEST_ENABLED) {
            JSONObject response = new JSONObject();
            response.put("transTP", "20");
            response.put("challenge", "");
            response.put("status", "attest_disabled");
            sendResponse(response, "20", generateMessageId());
            return;
        }

        String challenge = AttestationChallengeCache.generateChallenge();

        JSONObject response = new JSONObject();
        response.put("transTP", "20");
        response.put("challenge", challenge);
        response.put("status", "success");

        sendResponse(response, "20", generateMessageId());
        Log.d("📤 挑战响应已发送: " + challenge.substring(0, 16) + "...");
    }

    private void handleAttestation(JSONObject json) throws JSONException {
        String keyId = json.getString("keyId");
        String attestation = json.getString("attestation");
        String challenge = json.getString("challenge");
        String userPath = json.optString("userPath", "");

        if (userPath.isEmpty()) {
            JSONObject response = new JSONObject();
            response.put("transTP", "21");
            response.put("status", "error");
            response.put("message", "Missing userPath");
            sendResponse(response, "21", generateMessageId());
            return;
        }

        if (!ATTEST_ENABLED) {
            JSONObject response = new JSONObject();
            response.put("transTP", "21");
            response.put("status", "success");
            response.put("message", "Attestation disabled");
            response.put("userPath", userPath);
            sendResponse(response, "21", generateMessageId());
            Log.d("⚠️ Attest 已禁用，跳过验证: userPath=" + userPath + ", keyId=" + keyId);
            return;
        }

        Log.d("🔐 收到 Attestation: userPath=" + userPath + ", keyId=" + keyId);

        if (!AttestationChallengeCache.validateAndConsume(challenge)) {
            JSONObject response = new JSONObject();
            response.put("transTP", "21");
            response.put("status", "error");
            response.put("message", "Invalid or expired challenge");
            sendResponse(response, "21", generateMessageId());
            return;
        }

        PublicKey publicKey = AppAttestVerifier.verifyAttestation(
                attestation, challenge, keyId, userPath
        );

        if (publicKey == null) {
            JSONObject response = new JSONObject();
            response.put("transTP", "21");
            response.put("status", "error");
            response.put("message", "Attestation verification failed");
            sendResponse(response, "21", generateMessageId());
            return;
        }

        AttestationKeyStore.put(keyId, publicKey);

        JSONObject response = new JSONObject();
        response.put("transTP", "21");
        response.put("status", "success");
        response.put("message", "Attestation completed");
        sendResponse(response, "21", generateMessageId());

        Log.d("✅ Attestation 完成: userPath=" + userPath + ", keyId=" + keyId);
    }

    private boolean verifyBusinessRequest(JSONObject json, String rawMessage) {
        if (!ATTEST_ENABLED) {
            return true;
        }
        if (!json.has("attestation")) {
            Log.d("⚠️ 请求缺少 attestation 字段，拒绝");
            return false;
        }

        JSONObject attestation = json.getJSONObject("attestation");
        String keyId = attestation.getString("keyId");
        String assertion = attestation.getString("assertion");
        long timestamp = attestation.getLong("timestamp");

        PublicKey publicKey = AttestationKeyStore.getPublicKeyByKeyId(keyId);
        if (publicKey == null) {
            Log.d("❌ 未找到公钥: keyId=" + keyId);
            return false;
        }

        Log.d("🔐 验证 Assertion:  keyId=" + keyId);
        Log.d("🔐 服务器使用的公钥 (Base64): " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        // 4. 检查时间戳（防重放）
        long now = System.currentTimeMillis();
        if (Math.abs(now - timestamp) > 60000) {
            Log.d("❌ 请求时间戳过期: " + timestamp);
            return false;
        }
        String clientDataHashBase64 = attestation.optString("clientDataHash", "");
        Log.d("🔐 收到的 clientDataHash (Base64): " + clientDataHashBase64);
        if (clientDataHashBase64.isEmpty()) {
            Log.d("⚠️ 请求缺少 clientDataHash，降级使用服务器计算");
            JSONObject dataWithoutAttestation = new JSONObject(rawMessage);
            dataWithoutAttestation.remove("attestation");
            String dataString = dataWithoutAttestation.toString();
            byte[] dataBytes = dataString.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            clientDataHashBase64 = Base64.getEncoder().encodeToString(
                    AppAttestVerifier.sha256(dataBytes)
            );
        }

        boolean verified = AppAttestVerifier.verifyAssertion(
                assertion,
                clientDataHashBase64,
                keyId,       // ✅ 传入 keyId
                publicKey       // ✅ 传入公钥
        );

        if (verified) {
            Log.d("✅ Assertion 验证通过:  keyId=" + keyId);
        } else {
            Log.d("❌ Assertion 验证失败:  keyId=" + keyId);
        }

        return verified;
    }
    private boolean sendMessageToSocket(SSLSocket targetSocket, String message, String messageId, String operation, String targetInfo) {
        PrintWriter targetWriter = null;
        try {
            if (!isSocketValid(targetSocket)) {
                return false;
            }

            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
            String base64Encoded = Base64.getEncoder().encodeToString(messageBytes);
            String framedMessage = base64Encoded.length() + ":" + base64Encoded + "\n";


            targetWriter = new PrintWriter(
                    new BufferedWriter(
                            new OutputStreamWriter(targetSocket.getOutputStream(), StandardCharsets.UTF_8),
                            BUFFER_SIZE
                    ),
                    false);

            targetWriter.write(framedMessage);
            targetWriter.flush();

            if (targetWriter.checkError()) {
                targetWriter = new PrintWriter(
                        new BufferedWriter(
                                new OutputStreamWriter(targetSocket.getOutputStream(), StandardCharsets.UTF_8),
                                BUFFER_SIZE
                        ),
                        false);
                targetWriter.write(framedMessage);
                targetWriter.flush();

                if (targetWriter.checkError()) {
                    return false;
                } else {
                    return true;
                }
            }

            return true;

        } catch (Exception e) {
            return false;
        }
    }
    private void handleJsonMessage(JSONObject json, String originalMessage) throws JSONException {
        if (!json.has("transTP")) {
            sendErrorResponse("Missing required field 'transTP'");
            return;
        }

        String transTP = json.getString("transTP");
        OperationType operation = OperationType.fromCode(transTP);

        // 生成消息ID并记录收到的消息
        String messageId = generateMessageId();

        switch (operation) {
            case HEARTBEAT:
                handleHeartbeat(json, messageId);
                break;
            case UPDATE_MAPPING:
                handleUpdateMapping(json, messageId);
                break;
            case REGISTER_SOCKET:
                handleRegisterSocket(json, messageId);
                break;
            case QUERY_ID_PATHS:
                handleQueryIdPaths(json, messageId);
                break;
            case LOGOUT:
                handleLogout(json, messageId);
                break;
            case ONLINE_STATUS_QUERY:
                handleOnlineStatusQuery(json, messageId);
                break;

            case FORWARD_MESSAGE:
            case PATH_BROADCAST:
            case AVATAR_REQUEST:
            case AVATAR_RESPONSE:
                handleGenericMessage(json, messageId, transTP);
                break;

            case UNKNOWN:
            default:
                sendErrorResponse("Unsupported operation type: " + transTP);
                break;
        }
    }

    private void handleGenericMessage(JSONObject json, String messageId, String transTP) {
        // 提取公共字段
        String fromID = json.optString("fromID", "").trim();
        String toID = json.optString("toID", "").trim();
        String targetPath = json.optString("idpath", "").trim();
        String weMessage = json.getString("weMessage");
        // 1. 立即返回 40 确认响应
        sendAckResponse(messageId);

        // 2. 异步转发
        forwardExecutor.submit(() -> {
            performGenericForwarding(targetPath, weMessage, toID, fromID, messageId, transTP, json);
        });
    }

    private void sendAckResponse(String messageId) {
        try {
            JSONObject ackResponse = new JSONObject();
            ackResponse.put("transTP", "40");
            ackResponse.put("status", "processing");
            ackResponse.put("message", "转发请求已接收");

            String responseStr = ackResponse.toString();
            byte[] responseBytes = responseStr.getBytes(StandardCharsets.UTF_8);
            String base64Response = Base64.getEncoder().encodeToString(responseBytes);
            String framedResponse = base64Response.length() + ":" + base64Response + "\n";

            writer.write(framedResponse);

            int count = pendingWrites.incrementAndGet();
            long now = System.currentTimeMillis();
            if (count >= FLUSH_THRESHOLD || (now - lastFlushTime) >= FLUSH_INTERVAL_MS) {
                writer.flush();
                pendingWrites.set(0);
                lastFlushTime = now;
            }

            Log.d("📤 [SVR] 40 ACK sent msgId:" + messageId);
        } catch (Exception e) {
            Log.d("❌ [SVR] sendAckResponse failed msgId:" + messageId + " " + e.getMessage());
        }
    }

    /**
     * 通用转发逻辑
     */
    private void performGenericForwarding(String targetPath, String weMessage,
                                          String toID, String fromID,
                                          String messageId, String transTP,
                                          JSONObject originalJson) {
        Log.d("📤 [SVR] " + transTP + " forward start msgId:" + messageId + " targetPath:" + targetPath + " poolContains:" + socketPool.containsKey(targetPath));

        // 目标不在线，直接丢弃（由客户端处理离线逻辑）
        if (targetPath == null || targetPath.isEmpty() || !socketPool.containsKey(targetPath)) {
            Log.d("❌ [SVR] " + transTP + " target offline, DISCARDED msgId:" + messageId + " path:" + targetPath);
            return;
        }

        SSLSocket targetSocket = socketPool.get(targetPath);
        if (targetSocket == null || !isSocketValid(targetSocket)) {
            Log.d("❌ [SVR] " + transTP + " target socket invalid, DISCARDED msgId:" + messageId);
            return;
        }

        String targetAddr = targetSocket.getInetAddress().getHostAddress() + ":" + targetSocket.getPort();

        try {
            JSONObject forwardMessage = new JSONObject();

            // ✅ 只有 04 消息转发时改为 08，其他保持原值
            String outTransTP = transTP;
            if ("04".equals(transTP)) {
                outTransTP = "08";
            }
            Log.d("🔄 [SVR] " + transTP + " -> " + outTransTP + " msgId:" + messageId + " (04改08)");

            forwardMessage.put("transTP", outTransTP);
            forwardMessage.put("weMessage", weMessage);


            if (fromID != null && !fromID.isEmpty()) {
                forwardMessage.put("fromID", fromID);
                Log.d("✅ [SVR] 已添加 fromID 到转发消息: " + fromID);
            } else {
                Log.d("⚠️ [SVR] fromID 为空，跳过添加");
            }

            // 保留 forwardID 字段（从 originalJson 获取）
            if (originalJson.has("forwardID")) {
                String forwardID = originalJson.optString("forwardID", "");
                if (!forwardID.isEmpty()) {
                    forwardMessage.put("forwardID", forwardID);
                }
            }

            boolean success = sendMessageToSocket(targetSocket, forwardMessage.toString(),
                    messageId, outTransTP, targetAddr);

            if (success) {
                Log.d("✅ [SVR] " + transTP + " forward SUCCESS msgId:" + messageId + " to " + targetAddr + " (sent as " + outTransTP + ")");
            } else {
                Log.d("❌ [SVR] " + transTP + " forward FAILED msgId:" + messageId);
            }
        } catch (Exception e) {
            Log.d("❌ [SVR] " + transTP + " forward EXCEPTION msgId:" + messageId + " " + e.getMessage());
        }
    }


    private void handleOnlineStatusQuery(JSONObject json, String messageId) throws JSONException {
        String contactPath = json.getString("contactPath");
        boolean isOnline = socketPool.containsKey(contactPath);
        Log.d("📡 [SVR] 07 QUERY msgId:" + messageId + " path:" + contactPath + " isOnline:" + isOnline);
        JSONObject response = new JSONObject();
        response.put("transTP", "07");
        response.put("status", "success");
        response.put("isOnline", isOnline);
        response.put("contactPath", contactPath);

        sendResponse(response, "07", messageId);
    }


    private void handleLogout(JSONObject json, String messageId) throws JSONException {
        String userPath = json.getString("userPath");
        boolean existed = socketPool.containsKey(userPath);

        JSONObject response = new JSONObject();
        response.put("transTP", "06");
        response.put("status", "success");
        response.put("operation", "LOGOUT");
        response.put("userPath", userPath);
        response.put("removed", existed);

        sendResponse(response, "06", messageId);
        // 打印准备删除的数据
        if (existed) {
            socketPool.remove(userPath);  // 从socketPool删除记录
            if (clientSocket != null && !clientSocket.isClosed()) {
                try {
                    clientSocket.close();
                    Log.d("[LOGOUT] " + messageId + " socket已关闭");
                } catch (IOException e) {
                    Log.e("[LOGOUT] " + messageId + " 关闭socket异常: " + e.getMessage());
                }
            }
        }

        Log.d("LOGOUT| " + messageId + " | path:" + userPath + " | existed:" + existed);


        Log.d("[LOGOUT] " + messageId + " 清理完成 | 剩余池大小=" + socketPool.size());
        if (!socketPool.isEmpty()) {
            Log.d("[LOGOUT] " + messageId + " 当前socketPool内容:");
            for (Map.Entry<String, SSLSocket> entry : socketPool.entrySet()) {
                SSLSocket s = entry.getValue();
                String addr = s != null ? s.getInetAddress().getHostAddress() + ":" + s.getPort() : "closed";
                Log.d("  - userPath=" + entry.getKey() + " | client=" + addr);
            }
        } else {
            Log.d("[LOGOUT] " + messageId + " socketPool为空");
        }


    }

    private void handleCleanSocketOnly(JSONObject json) throws JSONException {
        String userPath = json.getString("userPath");

        Log.d("🧹 收到清理Socket请求: userPath=" + userPath);
        Log.d("🧹 [16-BEFORE] socketPool 大小: " + socketPool.size());
        for (Map.Entry<String, SSLSocket> entry : socketPool.entrySet()) {
            SSLSocket s = entry.getValue();
            String addr = s != null ? s.getInetAddress().getHostAddress() + ":" + s.getPort() : "closed";
            Log.d("🧹 [16-BEFORE]   " + entry.getKey() + " -> " + addr);
        }
        boolean existed = socketPool.containsKey(userPath);
        Log.d("🧹 [16] 查找 userPath: " + userPath + ", 存在: " + existed);
        if (existed) {
            SSLSocket socket = socketPool.remove(userPath);
            if (socket != null && !socket.isClosed()) {
                try {
                    socket.close();
                    Log.d("🧹 [16] Socket已关闭: " + socket.getInetAddress().getHostAddress() + ":" + socket.getPort());
                } catch (IOException e) {
                    Log.e("❌ 关闭Socket异常: " + e.getMessage());
                }
            }
            Log.d("🧹 [16-AFTER] socketPool 大小: " + socketPool.size());
            for (Map.Entry<String, SSLSocket> entry : socketPool.entrySet()) {
                SSLSocket s = entry.getValue();
                String addr = s != null ? s.getInetAddress().getHostAddress() + ":" + s.getPort() : "closed";
                Log.d("🧹 [16-AFTER]   " + entry.getKey() + " -> " + addr);
            }
        } else {
            Log.d("⚠️ Socket不存在: userPath=" + userPath);
        }

        JSONObject response = new JSONObject();
        response.put("transTP", "16");
        response.put("status", "success");
        response.put("message", "Socket cleaned, certificate retained");
        response.put("userPath", userPath);
        response.put("removed", existed);

        sendResponse(response, "16", generateMessageId());
        Log.d("✅ 清理Socket响应已发送: userPath=" + userPath + ", removed=" + existed);
    }

    private void handleCheckCertificate(JSONObject json) {
        Log.d("⏱️ [15-SERVER] ========== START ==========");
        if (!ATTEST_ENABLED) {
            JSONObject response = new JSONObject();
            response.put("transTP", "15");
            response.put("status", "success");
            response.put("exists", true);
            sendResponse(response, "15", generateMessageId());
            Log.d("⚠️ Attest 已禁用，返回 exists=true");
            return;
        }

        try {
            Log.d("🔍 [15-SERVER] 检查 attestation 字段...");
            if (!json.has("attestation")) {
                Log.d("❌ [15-SERVER] 缺少 attestation 字段，拒绝");
                sendErrorResponse("App attestation verification failed");
                return;
            }

            JSONObject attestation = json.getJSONObject("attestation");
            String keyId = attestation.getString("keyId");

            PublicKey publicKey = AttestationKeyStore.getPublicKeyByKeyId(keyId);
            boolean exists = (publicKey != null);
            if (exists) {
                Log.d("✅ [15-SERVER] 证书存在: keyId=" + keyId);
            } else {
                Log.d("❌ [15-SERVER] 证书不存在: keyId=" + keyId);
            }

            JSONObject response = new JSONObject();
            response.put("transTP", "15");
            response.put("status", "success");
            response.put("exists", exists);

            sendResponse(response, "15", generateMessageId());

            Log.d("✅ [15-SERVER] 查询结果: keyId=" + keyId + ", exists=" + exists);

        } catch (JSONException e) {
            Log.e("❌ [15-SERVER] 处理异常: " + e.getMessage());
            e.printStackTrace();
            sendErrorResponse("Invalid request");
        }
    }

    private void handleHeartbeat(JSONObject json, String messageId) throws JSONException {
        JSONObject response = new JSONObject();
        response.put("transTP", "05");
        response.put("heartbeat", "pong");
        response.put("timestamp", json.optLong("timestamp", System.currentTimeMillis()));

        sendResponse(response, "05", messageId);
    }


    private void handleUpdateMapping(JSONObject json, String messageId) throws JSONException {
        String userID = json.getString("userID");
        String path = json.getString("path");

        idPathPool.put(userID, path);

        JSONObject response = new JSONObject();
        response.put("status", "success");
        response.put("operation", "UPDATE_MAPPING");
        response.put("userID", userID);
        response.put("pointFeatureEnabled", POINT_FEATURE_ENABLED);
        response.put("loginBonusPoints", LOGIN_BONUS_POINTS);

        sendResponse(response, "01", messageId);
    }


    private void handleRegisterSocket(JSONObject json, String messageId) throws JSONException {
        String userPath = json.getString("userPath");
        for (Map.Entry<String, SSLSocket> entry : socketPool.entrySet()) {
            SSLSocket s = entry.getValue();
        }

        Iterator<Map.Entry<String, SSLSocket>> iterator = socketPool.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, SSLSocket> entry = iterator.next();
            if (entry.getValue().equals(clientSocket)) {
                Log.d("📝 [02] 移除旧映射: " + entry.getKey() + " (同一socket)");
                iterator.remove();
            }
        }

        SSLSocket previousSocket = socketPool.put(userPath, clientSocket);
        if (previousSocket != null) {
            Log.d("📝 [02] 替换旧记录: " + userPath + " (旧socket: " + previousSocket.getInetAddress().getHostAddress() + ":" + previousSocket.getPort() + ")");
        }

        Log.d("📝 [02-AFTER] socketPool 大小: " + socketPool.size());
        for (Map.Entry<String, SSLSocket> entry : socketPool.entrySet()) {
            SSLSocket s = entry.getValue();
            String addr = s != null ? s.getInetAddress().getHostAddress() + ":" + s.getPort() : "closed";
            Log.d("📝 [02-AFTER]   " + entry.getKey() + " -> " + addr);
        }
        Log.d("REG| after | poolSize:" + socketPool.size() + " keys:" + socketPool.keySet());
        // 打印注册结果
        Log.d("[" + new Date() + "] [" + messageId + "] REGISTER userPath=" + userPath +
                " poolSize=" + socketPool.size() + " keys=" + String.join(",", socketPool.keySet()));

        JSONObject response = new JSONObject();
        response.put("transTP", "02");
        response.put("status", "success");
        response.put("operation", "REGISTER_SOCKET");
        response.put("userPath", userPath);

        sendResponse(response, "02", messageId);
    }


    private void handleQueryIdPaths(JSONObject json, String messageId) throws JSONException {
        String idListStr = json.getString("idList");
        String[] ids = idListStr.split("\\|");

        List<String> idPathPairs = new ArrayList<>();
        for (String id : ids) {
            String path = idPathPool.get(id);

            String pair = path != null ? id + ":" + path : id + ":";
            idPathPairs.add(pair);
        }

        String resultList = String.join("|", idPathPairs);

        JSONObject response = new JSONObject();
        response.put("transTP", "03");
        response.put("status", "success");
        response.put("operation", "QUERY_ID_PATHS");
        response.put("idPathList", resultList);

        sendResponse(response, "03", messageId);
    }


    private boolean isSocketValid(SSLSocket socket) {
        if (socket == null || socket.isClosed() || !socket.isConnected()) {
            return false;
        }

        try {
            socket.getOutputStream().flush();
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    private boolean shouldFlushImmediately(String operation) {
        return "05".equals(operation) ||
                "02".equals(operation) ||
                "06".equals(operation) ||
                "ERROR".equals(operation) ||
                "16".equals(operation) ||
                "15".equals(operation);
    }

    private void sendErrorResponse(String errorMessage) {
        JSONObject response = new JSONObject();
        response.put("status", "error");
        response.put("message", errorMessage);

        String messageId = generateMessageId();
        sendResponse(response, "ERROR", messageId);
        Log.e("[" + new Date() + "] [" + messageId + "] Error: " + errorMessage);
    }


    private void sendResponse(JSONObject json, String operation, String messageId) {
        synchronized (this) {
            try {
                if (writer == null || writer.checkError()) {
                    writer = new PrintWriter(
                            new BufferedWriter(
                                    new OutputStreamWriter(clientSocket.getOutputStream(), StandardCharsets.UTF_8),
                                    BUFFER_SIZE
                            ),
                            false);
                    lastFlushTime = System.currentTimeMillis();
                }

                String messageStr = json.toString();
                byte[] messageBytes = messageStr.getBytes(StandardCharsets.UTF_8);
                String base64Encoded = Base64.getEncoder().encodeToString(messageBytes);
                String framedMessage = base64Encoded.length() + ":" + base64Encoded + "\n";

                writer.write(framedMessage);

                if (shouldFlushImmediately(operation)) {
                    writer.flush();
                    pendingWrites.set(0);
                    lastFlushTime = System.currentTimeMillis();
                } else {
                    int count = pendingWrites.incrementAndGet();
                    long now = System.currentTimeMillis();
                    if (count >= FLUSH_THRESHOLD || (now - lastFlushTime) >= FLUSH_INTERVAL_MS) {
                        writer.flush();
                        pendingWrites.set(0);
                        lastFlushTime = now;
                    }
                }

                if ("02".equals(operation) || "03".equals(operation) || "06".equals(operation) || "16".equals(operation)) {
                    Log.d("📤 [SVR] " + operation + " response sent msgId:" + messageId);
                }
                if (writer.checkError()) {
                    cleanup();
                }
            } catch (Exception e) {
                cleanup();
            }
        }
    }


    private void cleanup() {
        try {
            Log.d("[DIAG] CLEANUP_CALLED");
            if (writer != null) {
                    if (pendingWrites.get() > 0) {
                        writer.flush();
                    }
                    writer.close();
            }
            if (clientSocket == null) {
                Log.d("[DIAG] CLEANUP clientSocket=null");
                return;
            }

            String clientAddr = clientSocket.getInetAddress().getHostAddress();
            int clientPort = clientSocket.getPort();
            Log.d("[DIAG] CLEANUP client=" + clientAddr + ":" + clientPort +
                    " closed=" + clientSocket.isClosed() +
                    " connected=" + clientSocket.isConnected());

            Log.d("[DIAG] CLEANUP poolSize=" + socketPool.size());
            for (Map.Entry<String, SSLSocket> entry : socketPool.entrySet()) {
                SSLSocket s = entry.getValue();
                if (s != null) {
                    String sAddr = s.getInetAddress().getHostAddress();
                    int sPort = s.getPort();
                    boolean match = sAddr.equals(clientAddr) && sPort == clientPort;
                    Log.d("  " + entry.getKey() + " -> " + sAddr + ":" + sPort + " match=" + match);
                }
            }

            boolean removed = false;
            Iterator<Map.Entry<String, SSLSocket>> iterator = socketPool.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, SSLSocket> entry = iterator.next();
                SSLSocket s = entry.getValue();
                if (s != null) {
                    try {
                        if (s.getPort() == clientPort &&
                                s.getInetAddress().getHostAddress().equals(clientAddr)) {
                            Log.d("[DIAG] CLEANUP_REMOVED_BY_ADDR path=" + entry.getKey());
                            iterator.remove();
                            removed = true;
                            break;
                        }
                        // 备用：如果地址匹配失败，尝试 ==
                        if (s == clientSocket) {
                            Log.d("[DIAG] CLEANUP_REMOVED_BY_REF path=" + entry.getKey());
                            iterator.remove();
                            removed = true;
                            break;
                        }
                    } catch (Exception e) {
                        Log.d("[DIAG] CLEANUP_CHECK_ERROR " + e.getMessage());
                    }
                }
            }

            if (!removed) {
                Log.d("[DIAG] CLEANUP_NO_MATCH");
            }

            Iterator<Map.Entry<Integer, SSLSocket>> portIterator = portSocketMap.entrySet().iterator();
            while (portIterator.hasNext()) {
                Map.Entry<Integer, SSLSocket> entry = portIterator.next();
                if (entry.getValue() == clientSocket) {
                    portIterator.remove();
                    Log.d("[DIAG] CLEANUP_PORT_REMOVED port=" + entry.getKey());
                    break;
                }
            }

            if (clientSocket != null && !clientSocket.isClosed()) {
                clientSocket.close();
            }
        } catch (Exception e) {
            Log.d("[DIAG] CLEANUP_EXCEPTION " + e.getMessage());
        }
    }
    private String findPathBySocket(SSLSocket socket) {
        if (socket == null) return "null";
        for (Map.Entry<String, SSLSocket> entry : socketPool.entrySet()) {
            if (entry.getValue() == socket) {
                return entry.getKey();
            }
        }
        return "not_found";
    }

    private enum OperationType {
        UPDATE_MAPPING("01"),
        REGISTER_SOCKET("02"),
        QUERY_ID_PATHS("03"),
        FORWARD_MESSAGE("04"),
        HEARTBEAT("05"),
        LOGOUT("06"),
        ONLINE_STATUS_QUERY("07"),
        PATH_BROADCAST("09"),
        GROUP_CONTACTS_SYNC("11"),
        AVATAR_REQUEST("12"),
        AVATAR_RESPONSE("13"),
        CHECK_CERTIFICATE("15"),
        CLEAN_SOCKET_ONLY("16"),
        PATH_BROADCAST_RESPONSE("90"),
        UNKNOWN("unknown");

        private final String code;

        OperationType(String code) {
            this.code = code;
        }

        public static OperationType fromCode(String code) {
            for (OperationType type : values()) {
                if (type.code.equals(code)) {
                    return type;
                }
            }
            return UNKNOWN;
        }
    }
}