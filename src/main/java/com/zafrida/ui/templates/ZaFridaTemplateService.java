package com.zafrida.ui.templates;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class ZaFridaTemplateService {

    private final List<ZaFridaTemplate> templates;

    public ZaFridaTemplateService() {
        this.templates = new ArrayList<>(BuiltInTemplates.all());
    }

    public @NotNull List<ZaFridaTemplate> all() {
        return new ArrayList<>(templates);
    }

    public @NotNull Optional<ZaFridaTemplate> findById(@NotNull String id) {
        for (ZaFridaTemplate t : templates) {
            if (t.getId().equals(id)) return Optional.of(t);
        }
        return Optional.empty();
    }
}
