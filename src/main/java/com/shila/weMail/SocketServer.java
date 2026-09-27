package com.shila.weMail;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.*;

public class SocketServer {
	private static final ConcurrentMap<String, String> idPath = new ConcurrentHashMap<>();
	private static final ConcurrentMap<String, SSLSocket> socketPool = new ConcurrentHashMap<>();
	// 🆕 新增：全局端口-Socket映射
	private static final ConcurrentMap<Integer, SSLSocket> portSocketMap = new ConcurrentHashMap<>();

	private static final ThreadPoolExecutor threadPool = new ThreadPoolExecutor(
			100,
			500,
			60L, TimeUnit.SECONDS,
			new LinkedBlockingQueue<>(2000),
			new ThreadPoolExecutor.DiscardPolicy()// 队列满时直接丢弃新任务
	);

	// 监控定时器
	private static Timer monitorTimer;
	private static long lastAcceptTime = System.currentTimeMillis();
	private static int servicePort = 18577;
	private static int failCount = 0;
	private static final long WARNING_TIME = 300000; // 5分钟
	public static void main(String[] args) {
		Runtime.getRuntime().addShutdownHook(new Thread(SocketServer::shutdown));

		startSimpleMonitor();
		startMinimalMonitor();
		try {
			SSLServerSocket serverSocket = (SSLServerSocket)
					SSLContextHelper.createSSLContext()
							.getServerSocketFactory()
							.createServerSocket(servicePort);


			serverSocket.setEnabledCipherSuites(new String[] {
					"TLS_AES_128_GCM_SHA256",
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
			});

			System.out.println("[" + new Date() + "] Server started on port "+servicePort);
			while (!Thread.currentThread().isInterrupted()) {
				try {
				SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
//					acceptCount++;
					lastAcceptTime = System.currentTimeMillis();
				clientSocket.setSoTimeout(60000);
				int clientPort = clientSocket.getPort();

				portSocketMap.put(clientPort, clientSocket);

					System.out.println("安全客户端已连接: " + clientSocket.getInetAddress() + ":" + clientPort);

				threadPool.execute(new ClientHandler(clientSocket, idPath, socketPool, portSocketMap));
				} catch (IOException e) {
					failCount++;
					Log.e("[" + new Date() + "] Accept failed: " + e.getMessage());
				}
			}
		} catch (Exception e) {
			Log.e("[" + new Date() + "] Server error: " + e.getMessage());
			e.printStackTrace();
		}
	}

	private static void startMinimalMonitor() {
		Thread monitor = new Thread(() -> {
			while (true) {
				try {
					Thread.sleep(60000); // 1分钟检查一次

					long now = System.currentTimeMillis();
					long idleTime = now - lastAcceptTime;

					// 只在长时间无连接时打印警告
					if (idleTime > WARNING_TIME) {
						Log.e("[" + new Date() + "] WARNING: No new connections for " +
								(idleTime / 1000) + " seconds! Pool size: " + socketPool.size());
					}

				} catch (InterruptedException e) {
					break;
				}
			}
		}, "Monitor");
		monitor.setDaemon(true);
		monitor.start();
	}

	private static void startSimpleMonitor() {
		monitorTimer = new Timer("Simple-Monitor", true);
		monitorTimer.scheduleAtFixedRate(new TimerTask() {
			@Override
			public void run() {
				// 打印状态信息
				Log.d("\n=== 服务器状态 ===");
				Log.d("线程池活动线程: " + threadPool.getActiveCount());
				Log.d("线程池队列大小: " + threadPool.getQueue().size());
				Log.d("线程池已完成任务: " + threadPool.getCompletedTaskCount());
				Log.d("线程池总任务: " + threadPool.getTaskCount());
				Log.d("socketPool大小: " + socketPool.size());
				Log.d("portSocketMap大小: " + portSocketMap.size());
				Log.d("idPath大小: " + idPath.size());
				Log.d("================\n");
			}
		}, 10000, 30000);  // 10秒后开始，每30秒打印一次
	}

	public static ConcurrentMap<Integer, SSLSocket> getPortSocketMap() {
		return portSocketMap;
	}
	private static void shutdown() {
		Log.d("Shutting down...");

		if (monitorTimer != null) {
			monitorTimer.cancel();
		}

		threadPool.shutdown();
		try {
			if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
				threadPool.shutdownNow();
			}
		} catch (InterruptedException e) {
			threadPool.shutdownNow();
			Thread.currentThread().interrupt();
		}

		socketPool.values().forEach(socket -> {
			try { if (socket != null && !socket.isClosed()) socket.close(); } catch (Exception e) {}
		});
		portSocketMap.values().forEach(socket -> {
			try { if (socket != null && !socket.isClosed()) socket.close(); } catch (Exception e) {}
		});

		idPath.clear();
		socketPool.clear();
		portSocketMap.clear();

		Log.d("Server stopped");
	}

}