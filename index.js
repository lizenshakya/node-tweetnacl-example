'use strict';

const createError = require('http-errors');
const express = require('express');
const morganLogger = require('morgan');

const nacl = require('tweetnacl');
nacl.util = require('tweetnacl-util');


const app = express();

const cors = require('cors');
app.use(cors());
app.options('*', cors());

app.use(morganLogger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
  req = Object.assign(req, {
    debugId: '',
    deviceId: req.get('User-Agent'),
    token: req.headers['x-access-token'] || req.headers.authorization
  })
  next();
});

app.get('/encrypt',(req, res, next) => {
    const exampleForEncryptData = "Hello There!!!!";
    const keyPairObj = nacl.box.keyPair();
    //publicKey: Uint8Array(32) [167, 10, 237, 203, 33, 228, 204, 158, 52, 41, 84, 47, 158, 244, 241, 132, 196, 116, 253, 124, 251, 99, 116, 97, 252, 37, 155, 86, 152, 91, 244, 79]
    //secretKey: Uint8Array(32) [216, 155, 204, 24, 3, 208, 51, 170, 59, 241, 186, 227, 36, 98, 60, 2, 77, 131, 80, 173, 5, 56, 146, 40, 25, 198, 110, 203, 191, 248, 152, 239]
    console.log(keyPairObj, "keyPairObj")
    const nonce = nacl.randomBytes(24);
    //nonce: Uint8Array(24) [97, 82, 183, 247, 182, 171, 201, 211, 65, 217, 223, 155, 133, 101, 200, 180, 9, 188, 29, 130, 19, 62, 218, 152]
    console.log(nonce, "==================")
    const secretKeyString = nacl.util.encodeBase64(keyPairObj.secretKey);
    //secretKeyString: '2JvMGAPQM6o78brjJGI8Ak2DUK0FOJIoGcZuy7/4mO8='
    const publicKeyString = nacl.util.encodeBase64(keyPairObj.publicKey);
    //publicKeyString: 'pwrtyyHkzJ40KVQvnvTxhMR0/Xz7Y3Rh/CWbVphb9E8='
    const nonceString = nacl.util.encodeBase64(nonce);
    //nonceString: 'YVK397arydNB2d+bhWXItAm8HYITPtqY'
    const utf8 = exampleForEncryptData;
    const box = nacl.box(
                    nacl.util.decodeUTF8(utf8),
                    nonce,
                    keyPairObj.publicKey,
                    keyPairObj.secretKey
                )
    //box: Uint8Array(31) [99, 201, 92, 252, 159, 55, 244, 129, 10, 56, 29, 183, 182, 18, 48, 125, 11, 35, 171, 73, 76, 187, 92, 140, 66, 95, 21, 122, 228, 159, 101]
    const encryptedData = nacl.util.encodeBase64(box);
    //encryptedData: "Y8lc/J839IEKOB23thIwfQsjq0lMu1yMQl8VeuSfZQ==",
    res.status(200);
    res.send({ encryptedData, secretKeyString, publicKeyString, nonceString  });
});

app.get('/decrypt',(req, res, next) => {
    const publicKeyString = 'pwrtyyHkzJ40KVQvnvTxhMR0/Xz7Y3Rh/CWbVphb9E8=';
    const secretKeyString = '2JvMGAPQM6o78brjJGI8Ak2DUK0FOJIoGcZuy7/4mO8=';
    const nonceString = 'YVK397arydNB2d+bhWXItAm8HYITPtqY';
    const encryptedData = "Y8lc/J839IEKOB23thIwfQsjq0lMu1yMQl8VeuSfZQ==";
    const publicKeyUint8 = nacl.util.decodeBase64(publicKeyString);
    const secretKeyUint8 = nacl.util.decodeBase64(secretKeyString);
    const nonceUint8 = nacl.util.decodeBase64(nonceString);
    const boxUint8 = nacl.util.decodeBase64(encryptedData);

    const payload = nacl.box.open(boxUint8, nonceUint8, publicKeyUint8, secretKeyUint8 );
    const utf8 = nacl.util.encodeUTF8(payload);
    res.status(200);
    res.send({ utf8 });
});

app.use((req, res, next) => {
  next(createError(404, 'api not found'));
});
app.use(function (err, req, res, next) {
  /* set locals, only providing error in development */

  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  /* render the error page */
  res.status(err.status || 500);
  res.send({ message: err.message || 'error' });
});

app.listen(3000, () => console.log('listing to port 3000'))
module.exports = app;
