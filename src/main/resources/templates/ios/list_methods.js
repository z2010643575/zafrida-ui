// List Class Methods
// 列出指定类的所有方法

var className = "TargetClass";
var methods = ObjC.classes[className].$ownMethods;
console.log("[*] Methods of " + className + ":");
for (var i = 0; i < methods.length; i++) {
    console.log("  " + methods[i]);
}