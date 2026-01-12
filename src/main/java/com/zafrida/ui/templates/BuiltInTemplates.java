package com.zafrida.ui.templates;

import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;

public final class BuiltInTemplates {

    private BuiltInTemplates() {
    }

    public static @NotNull List<ZaFridaTemplate> all() {
        List<ZaFridaTemplate> list = new ArrayList<>();

        list.add(new ZaFridaTemplate(
                "utils_on_message",
                "onMessage handler",
                "Standard send()/error message handler",
                ZaFridaTemplateCategory.UTILS,
                """
                // message handler (send()/error)
                recv(function (message) {
                  console.log("[recv] " + JSON.stringify(message));
                  recv(arguments.callee);
                });
                """.strip()
        ));

        list.add(new ZaFridaTemplate(
                "android_java_perform",
                "Android Java.perform() skeleton",
                "Basic Java.perform entry, safe hook place",
                ZaFridaTemplateCategory.ANDROID,
                """
                if (Java.available) {
                  Java.perform(function () {
                    console.log("[Android] Java.perform() entered");
                    // TODO: your hooks here
                  });
                } else {
                  console.log("[Android] Java is not available");
                }
                """.strip()
        ));

        list.add(new ZaFridaTemplate(
                "android_hook_method",
                "Android hook Java method sample",
                "Hook method via Java.use + overload + implementation",
                ZaFridaTemplateCategory.ANDROID,
                """
                if (Java.available) {
                  Java.perform(function () {
                    var ClzName = "java.lang.String";
                    var Clz = Java.use(ClzName);
                    // Example: hook String.length()
                    Clz.length.implementation = function () {
                      var ret = this.length();
                      console.log("[Hook] " + ClzName + ".length() => " + ret);
                      return ret;
                    };
                  });
                }
                """.strip()
        ));

        list.add(new ZaFridaTemplate(
                "ios_objc_available",
                "iOS ObjC.available guard",
                "Basic ObjC availability check",
                ZaFridaTemplateCategory.IOS,
                """
                if (ObjC.available) {
                  console.log("[iOS] ObjC is available");
                  // TODO: your hooks here
                } else {
                  console.log("[iOS] ObjC is not available");
                }
                """.strip()
        ));

        list.add(new ZaFridaTemplate(
                "native_interceptor_attach",
                "Native Interceptor.attach() sample",
                "Hook export symbol via Module.findExportByName + Interceptor.attach",
                ZaFridaTemplateCategory.NATIVE,
                """
                var sym = Module.findExportByName(null, "open");
                if (sym) {
                  console.log("[Native] open => " + sym);
                  Interceptor.attach(sym, {
                    onEnter: function (args) {
                      try {
                        console.log("[Native] open(path)=" + Memory.readUtf8String(args[0]));
                      } catch (e) {
                        console.log("[Native] open: failed read args[0]: " + e);
                      }
                    },
                    onLeave: function (retval) {
                    }
                  });
                } else {
                  console.log("[Native] export not found");
                }
                """.strip()
        ));

        list.add(new ZaFridaTemplate(
                "utils_rpc_exports",
                "rpc.exports skeleton",
                "Define rpc.exports for external controller calls",
                ZaFridaTemplateCategory.UTILS,
                """
                rpc.exports = {
                  ping: function () {
                    return "pong";
                  }
                };
                """.strip()
        ));

        return list;
    }
}
