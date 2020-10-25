"use strict";

((keyGenHelper)=>{
    const nacl = require('tweetnacl');
    nacl.util = require('tweetnacl-util');


    keyGenHelper.getKey = () => {
        try{
            const keyPairObj = nacl.box.keyPair();
            const nonce = nacl.randomBytes(24);
            const secretKeyString = nacl.util.encodeBase64(keyPairObj.secretKey);
            const publicKeyString = nacl.util.encodeBase64(keyPairObj.publicKey);
            const nonceString = nacl.util.encodeBase64(nonce);
            return  {
                keyPairObj,
                nonce,
                nonceString,
                secretKeyString,
                publicKeyString
            };
        } catch(error){
            throw new Error(error);
        }
    }
})(module.exports);