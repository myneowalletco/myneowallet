var BigInteger = require('bigi');
var ec = require('elliptic').ec;
var CryptoJS = require('crypto-js');
var ecurve = require('ecurve');
var Buffer = require('buffer').Buffer;
var baseX = require('base-x');
var secureRandom = require('secure-random');
var bs58check = require('bs58check');
var scrypt = require('js-scrypt');
var wif = require('wif');
module.exports = {
  BigInteger,
  CryptoJS,
  ec,
  ecurve,
  Buffer,
  baseX,
  secureRandom,
  bs58check,
  scrypt,
  wif,
  secureRandom
}