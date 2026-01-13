// SSL Pinning Bypass
// 绕过SSL证书校验

Java.perform(function() {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log('[*] SSL Pinning Bypassed for: ' + host);
        return untrustedChain;
    };
});