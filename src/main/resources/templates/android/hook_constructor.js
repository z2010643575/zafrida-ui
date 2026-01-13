// Hook Constructor
// Hook类的构造函数

Java.perform(function() {
    var targetClass = Java.use("com.example.TargetClass");
    targetClass.$init.overload('java.lang.String').implementation = function(arg) {
        console.log("[*] Constructor called with: " + arg);
        return this.$init(arg);
    };
});