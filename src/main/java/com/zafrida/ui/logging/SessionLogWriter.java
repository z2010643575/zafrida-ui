package com.zafrida.ui.logging;

import org.jetbrains.annotations.NotNull;

import java.io.BufferedWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

public final class SessionLogWriter {

    private final @NotNull Path file;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final LinkedBlockingQueue<String> queue = new LinkedBlockingQueue<>();
    private final BufferedWriter writer;
    private final Thread worker;

    public SessionLogWriter(@NotNull Path file) throws Exception {
        this.file = file;
        this.writer = Files.newBufferedWriter(
                file,
                StandardCharsets.UTF_8,
                StandardOpenOption.APPEND
        );

        this.worker = new Thread(this::runLoop, "ZAFrida-LogWriter");
        this.worker.setDaemon(true);
        this.worker.start();
    }

    private void runLoop() {
        try {
            while (running.get() || !queue.isEmpty()) {
                String item = queue.poll();
                if (item != null) {
                    writer.write(item);
                    writer.flush();
                } else {
                    try {
                        Thread.sleep(10);
                    } catch (InterruptedException ignored) {
                        // ignore
                    }
                }
            }
        } catch (Throwable ignored) {
            // ignore
        } finally {
            try {
                writer.flush();
            } catch (Throwable ignored) {
            }
            try {
                writer.close();
            } catch (Throwable ignored) {
            }
        }
    }

    public void append(@NotNull String text) {
        if (!running.get()) return;
        queue.offer(text);
    }

    public void close() {
        running.set(false);
        try {
            worker.join(500);
        } catch (InterruptedException ignored) {
        }
    }

    public @NotNull Path getFile() {
        return file;
    }
}
