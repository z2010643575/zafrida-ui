// Hook Objective-C Method
// Hook ObjC方法

var className = "TargetClass";
var methodName = "- targetMethod:";

var hook = ObjC.classes[className][methodName];
Interceptor.attach(hook.implementation, {
    onEnter: function(args) {
        console.log("[*] " + methodName + " called");
        console.log("[*] self: " + ObjC.Object(args[0]));
        console.log("[*] selector: " + ObjC.selectorAsString(args[1]));
    },
    onLeave: function(retval) {
        console.log("[*] Return: " + retval);
    }
});