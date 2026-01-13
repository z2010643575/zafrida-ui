// Enumerate Classes
// 枚举所有已加载的类

Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes("keyword")) {
                console.log("[*] Found: " + className);
            }
        },
        onComplete: function() {
            console.log("[*] Enumeration complete");
        }
    });
});