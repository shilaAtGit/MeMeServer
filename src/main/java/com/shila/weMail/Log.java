package com.shila.weMail;

import java.util.Date;

/**
 * 全局日志工具
 *
 * <p>设计目标：
 * <ul>
 *   <li>Debug 构建：正常输出日志到控制台</li>
 *   <li>Release 构建：所有日志代码在编译期被完全消除，零开销、零输出</li>
 * </ul>
 *
 * <p>使用方式：
 * <pre>{@code
 *   Log.d("用户已连接: " + ip);
 *   Log.w("队列已满");
 *   Log.e("Accept 失败", e);
 * }</pre>
 *
 * <p>如何切换 Debug / Release：
 * <ul>
 *   <li>方式一（推荐）：在构建时通过 javac 参数注入 <code>-Ddebug=true</code>，
 *       但更简单的是直接修改本文件的 {@link #DEBUG} 常量。</li>
 *   <li>方式二：用 Maven/Gradle 在 release 构建时用脚本把 {@code DEBUG = true}
 *       替换为 {@code DEBUG = false}。</li>
 * </ul>
 *
 * <p>注意：{@code DEBUG} 必须是 {@code static final boolean} 且是编译期常量，
 * 这样 Java 编译器才会做常量折叠，把 {@code if (DEBUG)} 块完全从字节码中移除。
 */
public final class Log {

    /**
     * 日志开关。
     *
     * <p>⚠️ 必须是 {@code static final boolean} 且赋值为字面量 {@code true/false}，
     * 否则编译器不会做常量折叠，Release 下就无法完全消除日志代码。
     *
     * <p>Debug 构建：改为 {@code true}
     * <br>Release 构建：改为 {@code false}
     */
    public static final boolean DEBUG = true;

    /** 是否在日志前加时间戳（Debug 下可开，方便排查） */
    private static final boolean WITH_TIMESTAMP = true;

    private Log() {
        // 工具类禁止实例化
    }

    // ==================== 基础方法 ====================

    public static void d(String tag, Object... items) {
        if (DEBUG) {
            System.out.println(format("📘", tag, items));
        }
    }

    public static void d(Object... items) {
        d(null, items);
    }

    public static void w(String tag, Object... items) {
        if (DEBUG) {
            System.out.println(format("⚠️", tag, items));
        }
    }

    public static void w(Object... items) {
        w(null, items);
    }

    public static void e(String tag, Object... items) {
        if (DEBUG) {
            System.err.println(format("❌", tag, items));
        }
    }

    public static void e(Object... items) {
        e(null, items);
    }

    /**
     * 带异常堆栈的错误日志。
     */
    public static void e(String tag, String message, Throwable t) {
        if (DEBUG) {
            System.err.println(format("❌", tag, message));
            t.printStackTrace(System.err);
        }
    }

    public static void e(String message, Throwable t) {
        e(null, message, t);
    }

    // ==================== 内部工具 ====================

    private static String format(String level, String tag, Object... items) {
        StringBuilder sb = new StringBuilder(64);

        if (WITH_TIMESTAMP) {
            sb.append('[').append(new Date()).append("] ");
        }

        sb.append(level).append(' ');

        // 自动捕获调用类名 + 行号（仅在 DEBUG 下执行，Release 下被折叠掉）
        if (DEBUG) {
            StackTraceElement caller = findCaller();
            if (caller != null) {
                sb.append('[').append(caller.getFileName())
                        .append(':').append(caller.getLineNumber()).append("] ");
            }
        }

        if (tag != null && !tag.isEmpty()) {
            sb.append('[').append(tag).append("] ");
        }

        if (items != null) {
            for (int i = 0; i < items.length; i++) {
                if (i > 0) sb.append(' ');
                sb.append(items[i]);
            }
        }

        return sb.toString();
    }

    /**
     * 找到日志调用者的栈帧。
     * 跳过 Log 自身的方法。
     */
    private static StackTraceElement findCaller() {
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        // 0: getStackTrace, 1: findCaller, 2: format, 3: d/w/e, 4: 真正的调用者
        for (int i = 3; i < stack.length; i++) {
            String cls = stack[i].getClassName();
            if (!cls.equals(Log.class.getName())) {
                return stack[i];
            }
        }
        return null;
    }
}