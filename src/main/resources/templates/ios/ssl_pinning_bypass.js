// iOS SSL Pinning Bypass
// 绕过iOS SSL证书校验

var resolver = new ApiResolver('objc');
resolver.enumerateMatches('-[* evaluateServerTrust:*]', {
    onMatch: function(match) {
        Interceptor.attach(match.address, {
            onEnter: function(args) {
                ObjC.Object(args[0]).setAlwaysTrust_(true);
            }
        });
    },
    onComplete: function() {}
});