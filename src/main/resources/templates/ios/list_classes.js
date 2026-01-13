// List ObjC Classes
// 列出所有ObjC类

for (var className in ObjC.classes) {
    if (ObjC.classes.hasOwnProperty(className)) {
        if (className.includes("keyword")) {
            console.log("[*] " + className);
        }
    }
}