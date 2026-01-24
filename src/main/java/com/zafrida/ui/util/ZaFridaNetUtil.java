package com.zafrida.ui.util;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * [工具类] Host/Port 规范化工具。
 * <p>
 * <strong>范围：</strong>
 * 仅做字符串/数值归一化，不进行网络访问或解析。
 */
public final class ZaFridaNetUtil {

    public static final String LOOPBACK_HOST = "127.0.0.1";
    public static final int DEFAULT_FRIDA_PORT = 14725;

    private ZaFridaNetUtil() {
    }

    /**
     * 归一化 host 文本（trim，null -> ""）。
     * @param host 原始 host
     * @return 规范化后的 host
     */
    public static @NotNull String normalizeHost(@Nullable String host) {
        if (host == null) return "";
        return host.trim();
    }

    /**
     * 归一化 host 文本，空值回退到 loopback。
     * @param host 原始 host
     * @return 规范化后的 host
     */
    public static @NotNull String defaultHost(@Nullable String host) {
        return defaultHost(host, LOOPBACK_HOST);
    }

    /**
     * 归一化 host 文本，空值回退到指定默认值。
     * @param host 原始 host
     * @param fallback 默认 host
     * @return 规范化后的 host
     */
    public static @NotNull String defaultHost(@Nullable String host, @NotNull String fallback) {
        String normalized = normalizeHost(host);
        return normalized.isEmpty() ? fallback : normalized;
    }

    /**
     * 端口为空时回退到默认端口。
     * @param port 原始端口
     * @return 规范化后的端口
     */
    public static int defaultPort(int port) {
        return defaultPort(port, DEFAULT_FRIDA_PORT);
    }

    /**
     * 端口为空时回退到指定端口。
     * @param port 原始端口
     * @param fallback 默认端口
     * @return 规范化后的端口
     */
    public static int defaultPort(int port, int fallback) {
        return port > 0 ? port : fallback;
    }

    /**
     * 判断 host 是否指向本机回环。
     * @param host 原始 host
     * @return 是否为 loopback
     */
    public static boolean isLoopbackHost(@Nullable String host) {
        String normalized = normalizeHost(host);
        return LOOPBACK_HOST.equals(normalized) || "localhost".equalsIgnoreCase(normalized);
    }
}
