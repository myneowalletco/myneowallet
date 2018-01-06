// original file: https://github.com/neotracker/neotracker-wallet/blob/6c612de7f38c80689260112cb271804f063a6b1c/src/wallet/shared/neon/utils.js

var hash160 = function(hex) {
  var programHexString = module.CryptoJS.enc.Hex.parse(hex);
  var programSha256 = module.CryptoJS.SHA256(programHexString);
  return module.CryptoJS.RIPEMD160(programSha256);
}

var hash256 = function(hex) {
  var hexEncoded = module.CryptoJS.enc.Hex.parse(hex)
  var programSha256 = module.CryptoJS.SHA256(hexEncoded)
  return module.CryptoJS.SHA256(programSha256).toString()
}

var ab2str = function(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

var str2ab = function(str) {
  var bufView = new Uint8Array(str.length);
  for (var i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return bufView;
}

var hexstring2ab = function(str) {
  var result = [];
  while (str.length >= 2) {
    result.push(parseInt(str.substring(0, 2), 16));
    str = str.substring(2, str.length);
  }
  return result;
}

var ab2hexstring = function(arr) {
  var result = "";
  for (var i = 0; i < arr.length; i++) {
    var str = arr[i].toString(16);
    str = str.length == 0 ? "00" :
      str.length == 1 ? "0" + str :
        str;
    result += str;
  }
  return result;
}

var reverseArray = function(arr) {
  var result = new Uint8Array(arr.length);
  for (var i = 0; i < arr.length; i++) {
    result[i] = arr[arr.length - 1 - i];
  }
  return result;
}

var numStoreInMemory = function(num, length) {
  for (var i = num.length; i < length; i++) {
    num = '0' + num;
  }
  var data = reverseArray(new module.Buffer(num, "HEX"));
  return ab2hexstring(data);
}

var stringToBytes = function(str) {
  var utf8 = unescape(encodeURIComponent(str));
  var arr = [];
  for (var i = 0; i < utf8.length; i++) {
    arr.push(utf8.charCodeAt(i));
  }
  return arr;
}

var getTransferTxData = function(txData) {
  var ba = new module.Buffer(txData, "hex");
  var Transaction = () => {
    this.type = 0;
    this.version = 0;
    this.attributes = "";
    this.inputs = [];
    this.outputs = [];
  };
  var tx = new Transaction();
  // Transfer Type
  if (ba[0] != 0x80) return;
  tx.type = ba[0];
  // Version
  tx.version = ba[1];
  // Attributes
  var k = 2;
  var len = ba[k];
  for (i = 0; i < len; i++) {
    k = k + 1;
  }
  // Inputs
  k = k + 1;
  len = ba[k];
  for (i = 0; i < len; i++) {
    tx.inputs.push({
      txid: ba.slice(k + 1, k + 33),
      index: ba.slice(k + 33, k + 35)
    });
    //console.log( "txid:", tx.inputs[i].txid );
    //console.log( "index:", tx.inputs[i].index );
    k = k + 34;
  }
  // Outputs
  k = k + 1;
  len = ba[k];
  for (i = 0; i < len; i++) {
    tx.outputs.push({
      assetid: ba.slice(k + 1, k + 33),
      value: ba.slice(k + 33, k + 41),
      scripthash: ba.slice(k + 41, k + 61)
    });
    //console.log( "outputs.assetid:", tx.outputs[i].assetid );
    //console.log( "outputs.value:", tx.outputs[i].value );
    //console.log( "outputs.scripthash:", tx.outputs[i].scripthash );
    k = k + 60;
  }
  return tx;
}

var reverseHex = function(hex) {
  if (typeof hex !== 'string') throw new Error('reverseHex expects a string');
  if (hex.length % 2 !== 0) throw new Error('Incorrect Length: ' + hex);
  var out = '';
  for (let i = hex.length - 2; i >= 0; i -= 2) {
    out += hex.substr(i, 2)
  }
  return out;
}

var sha256 = function(hex) {
  if (typeof hex !== 'string') throw new Error('reverseHex expects a string');
  if (hex.length % 2 !== 0) throw new Error('Incorrect Length: ' + hex);
  var hexEncoded = module.CryptoJS.enc.Hex.parse(hex);
  return module.CryptoJS.SHA256(hexEncoded).toString();
}

var num2hexstring = function(num, size, littleEndian) {
  if (littleEndian === undefined) {
    littleEndian = false;
  }
  if (size === undefined) {
    size = 1;
  }
  if (typeof num !== 'number') throw new Error('num must be numeric');
  if (num < 0) throw new RangeError('num is unsigned (>= 0)');
  if (size % 1 !== 0) throw new Error('size must be a whole integer');
  if (!Number.isSafeInteger(num)) throw new RangeError('num (' + num + ') must be a safe integer');
  size = size * 2;
  var hexstring = num.toString(16);
  hexstring = hexstring.length % size === 0 ? hexstring : ('0'.repeat(size) + hexstring).substring(hexstring.length);
  if (littleEndian) hexstring = reverseHex(hexstring);
  return hexstring;
}

var num2VarInt = function(num) {
  if (num < 0xfd) {
    return num2hexstring(num);
  } else if (num <= 0xffff) {
    // uint16
    return 'fd' + num2hexstring(num, 2, true);
  } else if (num <= 0xffffffff) {
    // uint32
    return 'fe' + num2hexstring(num, 4, true);
  } else {
    // uint64
    return 'ff' + num2hexstring(num, 8, true);
  }
}

var num2fixed8 = function(num, size) {
  if (size === undefined) {
    size = 8;
  }
  if (typeof num !== 'number') throw new Error('num must be numeric');
  if (size % 1 !== 0) throw new Error('size must be a whole integer');
  return num2hexstring(Math.round(num * Math.pow(10, 8)), size, true);
}