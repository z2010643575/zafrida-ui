// Hook Native Function
// Hook native层函数

Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        this.path = args[0].readUtf8String();
        console.log("[*] open(" + this.path + ")");
    },
    onLeave: function(retval) {
        console.log("[*] open returned: " + retval);
    }
});