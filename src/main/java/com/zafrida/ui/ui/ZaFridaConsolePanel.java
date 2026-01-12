package com.zafrida.ui.ui;

import com.intellij.execution.ui.ConsoleView;
import com.intellij.execution.ui.ConsoleViewContentType;
import com.intellij.execution.filters.TextConsoleBuilderFactory;
import com.intellij.openapi.Disposable;
import com.intellij.openapi.util.Disposer;
import com.intellij.openapi.project.Project;

import javax.swing.JPanel;
import java.awt.BorderLayout;

public final class ZaFridaConsolePanel extends JPanel implements Disposable {

    private final ConsoleView consoleView;

    public ZaFridaConsolePanel(Project project) {
        super(new BorderLayout());
        this.consoleView = TextConsoleBuilderFactory.getInstance()
                .createBuilder(project)
                .getConsole();
        add(consoleView.getComponent(), BorderLayout.CENTER);
    }

    public ConsoleView getConsoleView() {
        return consoleView;
    }

    public void clear() {
        consoleView.clear();
    }

    public void info(String message) {
        consoleView.print(message + "\n", ConsoleViewContentType.NORMAL_OUTPUT);
    }

    public void warn(String message) {
        consoleView.print(message + "\n", ConsoleViewContentType.LOG_WARNING_OUTPUT);
    }

    public void error(String message) {
        consoleView.print(message + "\n", ConsoleViewContentType.ERROR_OUTPUT);
    }

    @Override
    public void dispose() {
        Disposer.dispose(consoleView);
    }
}
