package com.zafrida.ui.frida;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class FridaOutputParsers {

    private FridaOutputParsers() {
    }

    /**
     * Parses output of `frida-ls-devices`.
     * Expected columns: Id  Type  Name
     */
    public static @NotNull List<FridaDevice> parseDevices(@NotNull String stdout) {
        String clean = stripAnsi(stdout).trim();
        if (clean.isEmpty()) return Collections.emptyList();

        List<String> lines = nonEmptyLines(clean);
        if (lines.isEmpty()) return Collections.emptyList();

        int headerIndex = indexOfHeader(lines, "Id");
        List<String> dataLines = headerIndex >= 0
                ? dropSeparators(lines.subList(headerIndex + 1, lines.size()))
                : lines;

        List<FridaDevice> out = new ArrayList<>();
        for (String line : dataLines) {
            String[] parts = splitBy2PlusSpaces(line, 3);
            if (parts.length >= 3) {
                out.add(new FridaDevice(parts[0].trim(), parts[1].trim(), parts[2].trim()));
            }
        }
        return out;
    }

    /**
     * Parses output of `frida-ps`.
     * Expected columns: PID  Name  Identifier
     */
    public static @NotNull List<FridaProcess> parseProcesses(@NotNull String stdout) {
        String clean = stripAnsi(stdout).trim();
        if (clean.isEmpty()) return Collections.emptyList();

        List<String> lines = nonEmptyLines(clean);
        if (lines.isEmpty()) return Collections.emptyList();

        int headerIndex = indexOfHeader(lines, "PID");
        List<String> dataLines = headerIndex >= 0
                ? dropSeparators(lines.subList(headerIndex + 1, lines.size()))
                : lines;

        List<FridaProcess> out = new ArrayList<>();
        for (String line : dataLines) {
            String[] parts = splitBy2PlusSpaces(line, 3);
            if (parts.length >= 2) {
                Integer pid = tryParseInt(parts[0].trim());
                String name = parts[1].trim();
                String identifier = parts.length >= 3 ? emptyToNull(parts[2].trim()) : null;
                out.add(new FridaProcess(pid, name, identifier));
            }
        }
        return out;
    }

    private static @NotNull List<String> nonEmptyLines(@NotNull String text) {
        String[] raw = text.split("\\R");
        List<String> lines = new ArrayList<>();
        for (String s : raw) {
            String t = s.trim();
            if (!t.isEmpty()) lines.add(s.trim());
        }
        return lines;
    }

    private static int indexOfHeader(@NotNull List<String> lines, @NotNull String headerStartsWith) {
        for (int i = 0; i < lines.size(); i++) {
            String t = lines.get(i).trim();
            if (t.regionMatches(true, 0, headerStartsWith, 0, headerStartsWith.length())) {
                return i;
            }
        }
        return -1;
    }

    private static @NotNull List<String> dropSeparators(@NotNull List<String> lines) {
        int idx = 0;
        while (idx < lines.size()) {
            String t = lines.get(idx).trim();
            if (t.isEmpty()) {
                idx++;
                continue;
            }
            boolean allDash = true;
            for (int i = 0; i < t.length(); i++) {
                if (t.charAt(i) != '-') {
                    allDash = false;
                    break;
                }
            }
            if (allDash) idx++;
            else break;
        }
        return lines.subList(idx, lines.size());
    }

    private static @NotNull String[] splitBy2PlusSpaces(@NotNull String line, int limit) {
        // Replace 2+ spaces with a single delimiter, then split.
        String normalized = line.trim().replaceAll(" {2,}", "\t");
        if (limit <= 0) return normalized.split("\t");
        return normalized.split("\t", limit);
    }

    private static Integer tryParseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static String emptyToNull(String s) {
        return s == null || s.isEmpty() ? null : s;
    }

    /**
     * Minimal ANSI escape removal (enough for most frida tools outputs).
     */
    private static @NotNull String stripAnsi(@NotNull String text) {
        StringBuilder sb = new StringBuilder(text.length());
        final char ESC = 27;
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c == ESC) {
                // Skip sequences like ESC [ ... m
                int j = i + 1;
                if (j < text.length() && text.charAt(j) == '[') {
                    j++;
                    while (j < text.length()) {
                        char cj = text.charAt(j);
                        if ((cj >= '0' && cj <= '9') || cj == ';') {
                            j++;
                            continue;
                        }
                        // Typically ends with 'm'
                        j++;
                        break;
                    }
                    i = j;
                    continue;
                }
            }
            sb.append(c);
            i++;
        }
        return sb.toString();
    }
}
