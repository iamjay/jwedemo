'use strict';

let jose = require('node-jose');

let keystore = jose.JWK.createKeyStore();

let appKey;
let eikonKey;

function generateKey() {
    let keylength = $("#keylength").find(":selected").text();
    let key = keystore.generate("RSA", parseInt(keylength))
        .then((key) => {
            appKey = key;
            $("#privateKey").val(key.toPEM(true));
            $("#publicKey").val(key.toPEM());
        });
}

function encryptToEikon() {
    let options = {
        format: 'compact'
    };
    return jose.JWE.createEncrypt(options, eikonKey)
        .update($("#payloadToEikon").val())
        .final()
        .then((result) => {
            $("#payloadToEikon").val(result);
        })
        .catch((err) => alert(err));
}

function encryptFromEikon() {
    if (!appKey) {
        alert("Please generate an app key first");
        return;
    }
    let options = {
        format: 'compact'
    };
    return jose.JWE.createEncrypt(options, appKey)
        .update($("#payloadFromEikon").val())
        .final()
        .then((result) => {
            $("#payloadFromEikon").val(result);
        })
        .catch((err) => alert(err));
}

function decrypt() {
    if (!appKey) {
        alert("Please generate an app key first");
        return;
    }
    return jose.JWE.createDecrypt(appKey)
        .decrypt($("#payloadFromEikon").val())
        .then((result) => {
            $("#payloadFromEikon").val(result.plaintext.toString());
        })
        .catch((err) => alert(err));
}

$("#privateKey").val("");
$("#publicKey").val("");

// Import Eikon's public key.
keystore.add($("#eikonPublicKey").val(), "pem") .then((key) => eikonKey = key);
