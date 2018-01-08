var constants = (function () {
  return {
    ADDR_VERSION: '17',
    ASSETS: {
      NEO: 'NEO',
      'c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b': 'NEO',
      GAS: 'GAS',
      '602c79718b16e442de58778e148d0b1084e3b2dffd5de6b7b16cee7969282de7': 'GAS'
    },
    DEFAULT_SCRYPT: {
      cost: 16384,
      blockSize: 8,
      parallel: 8,
      size: 64
    },
    NEP_HEADER: '0142',
    NEP_FLAG: 'e0'
  }
})();

var utils = (function (constants) {
  var _BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  var _base58 = module.baseX(_BASE58);
  function _generatePrivateKey() {
    return ab2hexstring(secureRandom(32));
  }
  function _getScriptHashFromAddress(address) {
    var hash = ab2hexstring(_base58.decode(address));
    return reverseHex(hash.substr(2, 40));
  }
  function _getAddressFromScriptHash(scriptHash) {
    var scriptHash = reverseHex(scriptHash);
    var shaChecksum = hash256(constants.ADDR_VERSION + scriptHash).substr(0, 8);
    return _base58.encode(module.Buffer.from(constants.ADDR_VERSION + scriptHash + shaChecksum, 'hex'));
  }
  function _isPrivateKey(privateKey) {
    return /^[0-9A-Fa-f]{64}$/.test(privateKey);
  }
  function _isPrivateKeyWIF(wif) {
    try {
      if (wif.length !== 52) return false;
      var hexStr = ab2hexstring(_base58.decode(wif));
      var shaChecksum = hash256(hexStr.substr(0, hexStr.length - 8)).substr(0, 8);
      return shaChecksum === hexStr.substr(hexStr.length - 8, 8);
    } catch (e) { return false };
  }
  function _isAddress(address) {
    try {
      var programHash = ab2hexstring(_base58.decode(address));
      var shaChecksum = hash256(programHash.slice(0, 42)).substr(0, 8);
      // We use the checksum to verify the address
      if (shaChecksum !== programHash.substr(42, 8)) return false;
      // As other chains use similar checksum methods, we need to attempt to transform the programHash back into the address
      var scriptHash = reverseHex(programHash.slice(2, 42));
      if (_getAddressFromScriptHash(scriptHash) !== address) {
        // address is not valid Neo address, could be btc, ltc etc.
        return false;
      }
      return true;
    } catch (e) { return false };
  }
  function _getPrivateKeyFromWIF(privateKeyWIF) {
    var data = _base58.decode(privateKeyWIF);
    if (data.length != 38 || data[0] != 0x80 || data[33] != 0x01) {
      // basic encoding errors
      return -1;
    }
    var dataHexString = module.CryptoJS.enc.Hex.parse(ab2hexstring(data.slice(0, data.length - 4)));
    var dataSha256 = module.CryptoJS.SHA256(dataHexString);
    var dataSha256_2 = module.CryptoJS.SHA256(dataSha256);
    var dataSha256Buffer = hexstring2ab(dataSha256_2.toString());
    if (ab2hexstring(dataSha256Buffer.slice(0, 4)) != ab2hexstring(data.slice(data.length - 4, data.length))) {
      //wif verify failed.
      return -2;
    }
    return data.slice(1, 33).toString("hex");
  }
  function _getVerificationScriptFromPublicKey(publicKeyEncoded) {
    return '21' + publicKeyEncoded.toString('hex') + 'ac';
  }
  function _toAddress(programHash) {
    var data = new Uint8Array(1 + programHash.length);
    data.set([23]);
    data.set(programHash, 1);
    var programHexString = module.CryptoJS.enc.Hex.parse(ab2hexstring(data));
    var programSha256 = module.CryptoJS.SHA256(programHexString);
    var programSha256_2 = module.CryptoJS.SHA256(programSha256);
    var programSha256Buffer = hexstring2ab(programSha256_2.toString());
    var datas = new Uint8Array(1 + programHash.length + 4);
    datas.set(data);
    datas.set(programSha256Buffer.slice(0, 4), 21);
    return _base58.encode(datas);
  }
  function _getPublicKeyFromPrivateKey(privateKey, encode) {
    if (encode === undefined) {
      encode = true;
    }
    var ecparams = module.ecurve.getCurveByName('secp256r1');
    var curvePt = ecparams.G.multiply(module.BigInteger.fromBuffer(hexstring2ab(privateKey)));
    return curvePt.getEncoded(encode);
  }
  function _getAddressFromPrivateKey(privateKey) {
    var accounts = [];
    var publicKeyEncoded = _getPublicKeyFromPrivateKey(privateKey, true);
    var publicKeyHash = hash160(publicKeyEncoded.toString('hex'));
    var script = _getVerificationScriptFromPublicKey(publicKeyEncoded);
    var programHash = hash160(script);
    var address = _toAddress(hexstring2ab(programHash.toString()));
    return address;
  }
  function _hexXor(str1, str2) {
    if (typeof str1 !== 'string' || typeof str2 !== 'string') {
      throw new Error('hexXor expects hex strings');
    }
    if (str1.length !== str2.length) {
      throw new Error('strings are disparate lengths');
    }
    if (str1.length % 2 !== 0) {
      throw new Error('strings must be hex');
    }
    var result = [];
    for (let i = 0; i < str1.length; i += 2) {
      result.push(parseInt(str1.substr(i, 2), 16) ^ parseInt(str2.substr(i, 2), 16))
    }
    return ab2hexstring(result)
  }
  return {
    generatePrivateKey: _generatePrivateKey,
    getPrivateKeyFromWIF: _getPrivateKeyFromWIF,
    getAddressFromPrivateKey: _getAddressFromPrivateKey,
    getVerificationScriptFromPublicKey: _getVerificationScriptFromPublicKey,
    getPublicKeyFromPrivateKey: _getPublicKeyFromPrivateKey,
    isPrivateKey: _isPrivateKey,
    getScriptHashFromAddress: _getScriptHashFromAddress,
    isAddress: _isAddress,
    base58: _base58,
    hexXor: _hexXor,
    sleep: function (time) {
      return new Promise(function(resolve) {
        setTimeout(resolve, time);
      });
    }
  }
})(constants);

var nep2 = (function () {
  function _ensureScryptParams (params) {
    return Object.assign({}, constants.DEFAULT_SCRYPT, params);
  }
  function _encrypt (wifKey, keyphrase, scryptParams) {
    if (scryptParams === undefined) {
      scryptParams = constants.DEFAULT_SCRYPT;
    }
    var privateKey = utils.getPrivateKeyFromWIF(wifKey);
    var address = utils.getAddressFromPrivateKey(privateKey);
    scryptParams = _ensureScryptParams(scryptParams);
    // SHA Salt (use the first 4 bytes)
    var SHA256 = module.CryptoJS.SHA256;
    var enc = module.CryptoJS.enc;
    var Buffer = module.Buffer;
    var scrypt = module.scrypt;
    var AES = module.CryptoJS.AES;
    var mode = module.CryptoJS.mode;
    var pad = module.CryptoJS.pad;
    var bs58check = module.bs58check;
    var addressHash = SHA256(SHA256(enc.Latin1.parse(address))).toString().slice(0, 8);
    // Scrypt
    var derived = scrypt.hashSync(
      Buffer.from(keyphrase.normalize('NFC'), 'utf8'),
      Buffer.from(addressHash, 'hex'),
      scryptParams
    ).toString('hex');
    var derived1 = derived.slice(0, 64);
    var derived2 = derived.slice(64);
    // AES Encrypt
    var xor = utils.hexXor(privateKey, derived1);
    var encrypted = AES.encrypt(
      enc.Hex.parse(xor),
      enc.Hex.parse(derived2),
      { mode: mode.ECB, padding: pad.NoPadding }
    );
    // Construct
    var assembled = constants.NEP_HEADER + constants.NEP_FLAG + addressHash + encrypted.ciphertext.toString();
    return bs58check.encode(Buffer.from(assembled, 'hex'));
  }
  function _decrypt (encryptedKey, keyphrase, scryptParams) {
    if (scryptParams === undefined) {
      scryptParams = constants.DEFAULT_SCRYPT;
    }
    scryptParams = _ensureScryptParams(scryptParams);
    var SHA256 = module.CryptoJS.SHA256;
    var enc = module.CryptoJS.enc;
    var Buffer = module.Buffer;
    var scrypt = module.scrypt;
    var AES = module.CryptoJS.AES;
    var mode = module.CryptoJS.mode;
    var pad = module.CryptoJS.pad;
    var bs58check = module.bs58check;
    var assembled = ab2hexstring(bs58check.decode(encryptedKey));
    var addressHash = assembled.substr(6, 8);
    var encrypted = assembled.substr(-64);
    var derived = scrypt.hashSync(
      Buffer.from(keyphrase.normalize('NFC'), 'utf8'),
      Buffer.from(addressHash, 'hex'),
      scryptParams).toString('hex');
    var derived1 = derived.slice(0, 64);
    var derived2 = derived.slice(64);
    var ciphertext = { ciphertext: enc.Hex.parse(encrypted), salt: '' };
    var decrypted = AES.decrypt(
      ciphertext,
      enc.Hex.parse(derived2), { mode: mode.ECB, padding: pad.NoPadding });
    var privateKey = utils.hexXor(decrypted.toString(), derived1);
    var address = utils.getAddressFromPrivateKey(privateKey);
    var newAddressHash = SHA256(SHA256(enc.Latin1.parse(address))).toString().slice(0, 8);
    if (addressHash !== newAddressHash) throw new Error('Wrong Password!');
    return [privateKey, address];
  }
  return {
    encrypt: _encrypt,
    decrypt: _decrypt
  }
})();

var network = (function () {
  var _DEFAULT_REQ = { jsonrpc: '2.0', method: 'getblockcount', params: [], id: 1234 };
  var _netType = 'MainNet';
  function _getAPIEndpoint(net) {
    switch(net) {
      case 'MainNet':
        return 'http://api.wallet.cityofzion.io'
      case 'TestNet':
        return 'http://testnet-api.wallet.cityofzion.io'
      default:
        return net
    }
  }
  function _getBalance(address) {
    var apiEndpoint = _getAPIEndpoint(_netType);
    return axios.get(apiEndpoint + '/v2/address/balance/' + address).then(function(res) {
      return res.data;
    });
  }
  function _getClaims(address) {
    var apiEndpoint = _getAPIEndpoint(_netType);
    return axios.get(apiEndpoint + '/v2/address/claims/' + address).then(function(res) {
      return res.data
    });
  }
  function _getRPCEndpoint() {
    var apiEndpoint = _getAPIEndpoint(_netType);
    return axios.get(apiEndpoint + '/v2/network/best_node').then(function(response) {
      return response.data.node
    });
  }
  function _getTransactionHistory(address) {
    var apiEndpoint = _getAPIEndpoint(_netType);
    return axios.get(apiEndpoint + '/v2/address/history/' + address).then(function(response) {
      return response.data.history
    });
  }
  function _getTransaction(transactionId) {
    var apiEndpoint = _getAPIEndpoint(_netType);
    return axios.get(apiEndpoint + '/v2/transaction/' + transactionId).then(function(response) {
      return response.data;
    });
  }
  function _queryRPC(url, req) {
    var jsonRequest = axios.create({ headers: { 'Content-Type': 'application/json' } })
    var jsonRpcData = Object.assign({}, _DEFAULT_REQ, req);
    return jsonRequest.post(url, jsonRpcData).then(function(response) {
      return response.data;
    });
  }
  function _Query (req) {
    this.req = Object.assign({}, _DEFAULT_REQ, req);
    this.completed = false;
    this.parse = null;
    this.execute = function(url) {
      if (this.completed) throw new Error('This request has been sent');
      return _queryRPC(url, this.req).then(function(res) {
        this.res = res;
        this.completed = true;
        if (res.error) {
          throw new Error(res.error.message);
        }
        if (this.parse) {
          return this.parse(res);
        }
        return res;
      });
    }
  }
  function _sendRawTransaction(serializedTransaction) {
    return new _Query({
      method: 'sendrawtransaction',
      params: [serializedTransaction]
    });
  }
  return {
    getAPIEndpoint: _getAPIEndpoint,
    getBalance: _getBalance,
    getClaims: _getClaims,
    getRPCEndpoint: _getRPCEndpoint,
    getTransactionHistory: _getTransactionHistory,
    getTransaction: _getTransaction,
    Query: _Query,
    queryRPC: _queryRPC,
    sendRawTransaction: _sendRawTransaction,
    setNetType: function(net) {
      _netType = net;
    },
    getNetType: function() {
      return _netType;
    }
  }
})();

var components = (function () {
  var _maxTransactionAttributeSize = 65535;
  var _serializeTransactionInput = function(input) {
    return reverseHex(input.prevHash) + reverseHex(num2hexstring(input.prevIndex, 2));
  }
  var _serializeTransactionAttribute = function(attr) {
    if (attr.data.length > _maxTransactionAttributeSize) throw new Error();
    var out = num2hexstring(attr.usage);
    if (attr.usage === 0x81) {
      out += num2hexstring(attr.data.length / 2);
    } else if (attr.usage === 0x90 || attr.usage >= 0xf0) {
      out += num2VarInt(attr.data.length / 2);
    }
    if (attr.usage === 0x02 || attr.usage === 0x03) {
      out += attr.data.substr(2, 64);
    } else {
      out += attr.data;
    }
    return out;
  }
  var _serializeTransactionOutput = function(output) {
    var value = num2fixed8(output.value);
    return reverseHex(output.assetId) + value + reverseHex(output.scriptHash);
  }
  var _serializeWitness = function(witness) {
    const invoLength = num2VarInt(witness.invocationScript.length / 2);
    const veriLength = num2VarInt(witness.verificationScript.length / 2);
    return invoLength + witness.invocationScript + veriLength + witness.verificationScript;
  }
  var _serializeTransaction = function(tx, signed) {
    if (signed === undefined) {
      signed = true;
    }
    var out = '';
    out += num2hexstring(tx.type);
    out += num2hexstring(tx.version);
    out += exclusive.serializeExclusive[tx.type](tx);
    out += num2VarInt(tx.attributes.length);
    for (var idx in tx.attributes) {
      var attribute = tx.attributes[idx];
      out += _serializeTransactionAttribute(attribute);
    }
    out += num2VarInt(tx.inputs.length);
    for (var idx in tx.inputs) {
      var input = tx.inputs[idx];
      out += _serializeTransactionInput(input);
    }
    out += num2VarInt(tx.outputs.length)
    for (var idx in tx.outputs) {
      var output = tx.outputs[idx];
      out += _serializeTransactionOutput(output);
    }
    if (signed && tx.scripts && tx.scripts.length > 0) {
      out += num2VarInt(tx.scripts.length)
      for (var idx in tx.scripts) {
        var script = tx.scripts[idx];
        out += _serializeWitness(script);
      }
    }
    return out;
  }
  return {
    serializeTransactionInput: _serializeTransactionInput,
    serializeTransactionAttribute: _serializeTransactionAttribute,
    serializeTransactionOutput: _serializeTransactionOutput,
    serializeWitness: _serializeWitness,
    serializeTransaction: _serializeTransaction
  }
})();

var exclusive = (function (components) {
  var _getClaimExclusive = function (tx) {
    return Object.assign({ claims: [] }, { claims: tx.claims });
  }
  var _getContractExclusive = function (tx) {
    return {};
  }
  var _getInvocationExclusive = function (tx) {
    return {
      script: tx.script || '',
      gas: tx.gas || 0
    }
  }
  var _serializeClaimExclusive = function(tx) {
    if (tx.type !== 0x02) throw new Error()
    var out = num2VarInt(tx.claims.length);
    for (var idx in tx.claims) {
      var claim = tx.claims[idx];
      out += components.serializeTransactionInput(claim);
    }
    return out;
  }
  var _serializeContractExclusive = function(tx) {
    if (tx.type !== 0x80) throw new Error();
    return '';
  }
  var _serializeInvocationExclusive = function(tx) {
    if (tx.type !== 0xd1) throw new Error();
    var out = num2VarInt(tx.script.length / 2);
    out += tx.script;
    if (tx.version >= 1) {
      out += num2fixed8(tx.gas);
    }
    return out;
  }
  var _serializeExclusive = {};
  _serializeExclusive[2] = _serializeClaimExclusive;
  _serializeExclusive[128] = _serializeContractExclusive;
  _serializeExclusive[209] = _serializeInvocationExclusive;
  var _exclusive = {};
  _exclusive[2] = _getClaimExclusive;
  _exclusive[128] = _getContractExclusive;
  _exclusive[209] = _getInvocationExclusive;
  return {
    serializeExclusive: _serializeExclusive,
    exclusive: _exclusive
  }
})(components);

var balanceManager = (function (constants) {
  var _bal = null;
  function Balance(bal) {
    this.assetSymbols = bal.assetSymbols ? bal.assetSymbols : [];
    this.assets = {};
    this.tokenSymbols = bal.tokenSymbols ? bal.tokenSymbols : [];
    this.tokens = bal.tokens ? bal.tokens : {};
    this.addAsset = function (sym, assetBalance = { balance: 0, spent: [], unspent: [], unconfirmed: [] }) {
      sym = sym.toUpperCase();
      this.assetSymbols.push(sym);
      var newBalance = Object.assign({ balance: 0, spent: [], unspent: [], unconfirmed: [] }, assetBalance);
      this.assets[sym] = JSON.parse(JSON.stringify(newBalance));
      return this;
    }
  }
  function _reset() {
    _bal = new Balance({});
  }
  _reset();
  return {
    getBalance: function () {
      return _bal;
    },
    update: function (netBal) {
      Object.keys(netBal).map(function(key) {
        if (key === 'net' || key === 'address') return;
        var parsedAsset = {
          balance: +(netBal[key].balance).toFixed(8),
          unspent: netBal[key].unspent.map(function(coin) {
            coin.value = +(coin.value).toFixed(8)
            return coin
          })
        }
        _bal.addAsset(key, parsedAsset);
      });
      Object.assign(_bal, netBal);
    },
    reset: function () {
      _reset();
    }
  }
})(constants);

var walletCore = (function (utils, components, exclusive, network, balanceManager) {
  var _netType = 'MainNet';
  var _address = null;
  var _privateKey = null;
  var _transactionHistory = null;
  var _ASSET_ID = {
    NEO: 'c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b',
    GAS: '602c79718b16e442de58778e148d0b1084e3b2dffd5de6b7b16cee7969282de7'
  };
  var _TX_VERSION = {
    'CLAIM': 0,
    'CONTRACT': 0,
    'INVOCATION': 0
  };
  function _generateSignature(tx, privateKey) {
    var msgHash = sha256(tx);
    var msgHashHex = module.Buffer.from(msgHash, 'hex');
    var elliptic = new module.ec('p256');
    var sig = elliptic.sign(msgHashHex, privateKey, null);
    var signature = module.Buffer.concat([
      sig.r.toArrayLike(module.Buffer, 'be', 32),
      sig.s.toArrayLike(module.Buffer, 'be', 32)
    ]);
    return signature.toString('hex');
  }
  function _calculateInputs(balances, intents, gasCost) {
    if (gasCost === undefined) {
      gasCost = 0;
    }
    if (intents === null) intents = [];
    var requiredAssets = intents.reduce(function(assets, intent) {
      var fixed8Value = Math.round(intent.value * 100000000);
      assets[intent.assetId] ? assets[intent.assetId] += fixed8Value : assets[intent.assetId] = fixed8Value;
      return assets;
    }, {});
    if (gasCost > 0) {
      var fixed8GasCost = gasCost * 100000000;
      requiredAssets[_ASSET_ID.GAS] ? requiredAssets[_ASSET_ID.GAS] += fixed8GasCost : requiredAssets[ASSET_ID.GAS] = fixed8GasCost;
    }
    var change = [];
    var inputs = Object.keys(requiredAssets).map(function(assetId) {
      var requiredAmt = requiredAssets[assetId];
      var assetSymbol = constants.ASSETS[assetId];
      if (balances.assetSymbols.indexOf(assetSymbol) === -1) {
        throw new Error('This balance does not contain any ' + assetSymbol + '!');
      }
      var assetBalance = balances.assets[assetSymbol];
      if (assetBalance.balance * 100000000 < requiredAmt) {
        throw new Error('Insufficient ' + constants.ASSETS[assetId] + '! Need ' + (requiredAmt / 100000000) + ' but only found ' + assetBalance.balance);
      }
      // Ascending order sort
      assetBalance.unspent.sort(function(a, b) { return a.value - b.value });
      var selectedInputs = 0;
      var selectedAmt = 0;
      // Selected min inputs to satisfy outputs
      while (selectedAmt < requiredAmt) {
        selectedInputs += 1;
        if (selectedInputs > assetBalance.unspent.length) {
          throw new Error('Insufficient ' + constants.ASSETS[assetId] + '! Reached end of unspent coins!');
        }
        selectedAmt += Math.round(assetBalance.unspent[selectedInputs - 1].value * 100000000);
      }
      // Construct change output
      if (selectedAmt > requiredAmt) {
        change.push({
          assetId,
          value: (selectedAmt - requiredAmt) / 100000000,
          scriptHash: utils.getScriptHashFromAddress(balances.address)
        })
      }
      // Format inputs
      return assetBalance.unspent.slice(0, selectedInputs).map(function(input) {
        return { prevHash: input.txid, prevIndex: input.index }
      });
    }).reduce(function(prev, curr) { prev.concat(curr), [] });
    return { inputs: inputs, change: change };
  }
  function _getTransactionHash(transaction) {
    return reverseHex(hash256(components.serializeTransaction(transaction, false)));
  }
  function _signTransaction(transaction, privateKey) {
    if (!utils.isPrivateKey(privateKey)) throw new Error('Key provided does not look like a private key!');
    var invocationScript = '40' + _generateSignature(components.serializeTransaction(transaction, false), privateKey);
    var verificationScript = utils.getVerificationScriptFromPublicKey(utils.getPublicKeyFromPrivateKey(privateKey));
    var witness = { invocationScript: invocationScript, verificationScript: verificationScript };
    transaction.scripts ? transaction.scripts.push(witness) : transaction.scripts = [witness];
    return transaction;
  }
  function Transaction(config, type, data) {
    var tx = Object.assign({
      type: 128,
      version: _TX_VERSION.CONTRACT,
      attributes: [],
      inputs: [],
      outputs: [],
      scripts: []
    }, config);
    this.type = tx.type;
    this.version = tx.version;
    this.attributes = tx.attributes;
    this.inputs = tx.inputs;
    this.outputs = tx.outputs;
    this.scripts = tx.scripts;
    var exclusiveFields = exclusive.exclusive[this.type](tx);
    var transaction = this;
    Object.keys(exclusiveFields).map(function(k) {
      transaction[k] = exclusiveFields[k];
    });
    this.calculate = function (balances) {
      var result = _calculateInputs(balances, this.outputs, this.gas);
      this.inputs = result.inputs;
      this.outputs = this.outputs.concat(result.change);
      return this;
    }
    this.sign = function(privateKey) {
      return _signTransaction(this, privateKey);
    }
    this.hash = function () {
      return _getTransactionHash(this);
    }
  }
  Transaction.createContractTx = function(balances, intents, override) {
    if (override === undefined) {
      override = {};
    }
    if (intents === null) throw new Error('Useless transaction!');
    var txConfig = Object.assign({
      type: 128,
      version: _TX_VERSION.CONTRACT,
      outputs: intents
    }, override);
    return new Transaction(txConfig).calculate(balances);
  }
  Transaction.createClaimTx = function(address, claimsData, override) {
    if (override === undefined) {
      override = {};
    }
    var txConfig = Object.assign({
      type: 2,
      version: _TX_VERSION.CLAIM
    }, override);
    var totalClaim = 0;
    var maxClaim = 255;
    txConfig.claims = claimsData.claims.slice(0, maxClaim).map(function(c) {
      totalClaim += c.claim;
      return {
        prevHash: c.txid,
        prevIndex: c.index
      }
    });
    txConfig.outputs = [{
      assetId: _ASSET_ID.GAS,
      value: totalClaim / 100000000,
      scriptHash: utils.getScriptHashFromAddress(address)
    }];
    return new Transaction(Object.assign(txConfig, override));
  }
  function _doSendAsset(to, from, assetsToSend, stateFunctions) {
    var intents = Object.keys(assetsToSend).map(function (key) {
      return {
        assetId: _ASSET_ID[key],
        value: assetsToSend[key],
        scriptHash: utils.getScriptHashFromAddress(to)
      }
    });
    var signedTx = null;
    var endPoint = null;
    return Promise.all([
      network.getRPCEndpoint(),
      network.getBalance(_address).then(function (netBal) {
        balanceManager.update(netBal);
        return balanceManager.getBalance();
      })
    ]).then(function (values) {
      endPoint = values[0];
      var balance = values[1];
      var unsignedTx = Transaction.createContractTx(balance, intents);
      if (stateFunctions !== undefined) {
        stateFunctions.successfully_built();
      }
      return unsignedTx.sign(_privateKey);
    }).then(function (signedResult) {
      if (stateFunctions !== undefined) {
        stateFunctions.successfully_signed();
      }
      signedTx = signedResult;
      return network.sendRawTransaction(components.serializeTransaction(signedTx)).execute(endPoint);
    }).then(function (res) {
      if (res.result === true) {
        res.txid = signedTx.hash();
        if (stateFunctions !== undefined) {
          stateFunctions.successfully_returned(res.txid);
        }
      } else {
        stateFunctions.error_validator_rejected();
      }
      return res;
    });
  }
  function _doClaimAllGas(address, stateFunctions) {
    var signedTx = null;
    var endPoint = null;
    return Promise.all([network.getRPCEndpoint(), network.getClaims(address)]).then(function (values) {
      endPoint = values[0];
      var claimsData = values[1];
      if (claimsData.claims.length === 0) {
        throw new Error('No claimable gas!');
      }
      var unsignedTx = Transaction.createClaimTx(address, claimsData);
      if (stateFunctions !== undefined) {
        stateFunctions.successfully_built();
      }
      return unsignedTx.sign(_privateKey);
    }).then(function (signedResult) {
      if (stateFunctions !== undefined) {
        stateFunctions.successfully_signed();
      }
      signedTx = signedResult;
      return network.sendRawTransaction(components.serializeTransaction(signedTx)).execute(endPoint);
    }).then(function (res) {
      if (res.result === true) {
        res.txid = signedTx.hash();
        if (stateFunctions !== undefined) {
          stateFunctions.successfully_returned(res.txid);
        }
      } else {
        stateFunctions.error_validator_rejected();
      }
      return res;
    });
  }
  var _refreshDisabledCounter = 2;
  function _waitForTransactionToConfirmRecursive(transactionId, confirmed, failed, iteration) {
    if (iteration == 24) {
      failed();
      return;
    }
    utils.sleep(5000).then(function () {
      network.getTransaction(transactionId).then(function () {
        confirmed();
      }).catch(function () {
        iteration += 1;
        _waitForTransactionToConfirmRecursive(transactionId, confirmed, failed, iteration);
      });
    });
  }
  function _waitForTransactionToConfirm(transactionId, confirmed, failed) {
    _waitForTransactionToConfirmRecursive(transactionId, confirmed, failed, 0)
  }
  function _refreshWallet() {
    if (_refreshDisabledCounter < 2) {
      return;
    }
    _refreshDisabledCounter = 0;
    var $wallet_summary_card = $('.wallet-summary-card');
    var $transaction_history_parent = $wallet_summary_card.find('.-transaction-history-parent');
    var $transaction_list_parent = $transaction_history_parent.find('.-transactions-list-parent');
    var $transaction_list = $transaction_list_parent.find('tbody');
    $transaction_history_parent.find('.-spinner-parent').show();
    $transaction_list_parent.hide();
    $transaction_list.html('');
    $wallet_summary_card.find('.-wallet-address').find('.-wallet-address-text').html(_address);
    $wallet_summary_card.find('.-neo-balance').find('.-value').html('...');
    $wallet_summary_card.find('.-gas-balance').find('.-value').html('...');
    $wallet_summary_card.find('.-claim-gas').find('.-value').html('...');
    network.getBalance(_address).then(
      function (netBal) {
        balanceManager.update(netBal);
        return balanceManager.getBalance();
      }
    ).then(
      function (balance) {
        _refreshDisabledCounter += 1;
        if (_refreshDisabledCounter == 2) {
          $wallet_summary_card.find('.-refresh-button').removeAttr("disabled");
        }
        $wallet_summary_card.find('.-neo-balance').find('.-value').html(balance.assets['NEO']['balance']);
        $wallet_summary_card.find('.-gas-balance').find('.-value').html(balance.assets['GAS']['balance']);
      }
    );
    network.getClaims(_address).then(function (claims) {
      _refreshDisabledCounter += 1;
      if (_refreshDisabledCounter == 2) {
        $wallet_summary_card.find('.-refresh-button').removeAttr("disabled");
      }
      $wallet_summary_card.find('.-claim-gas').find('.-value').html(claims.total_claim + claims.total_unspent_claim);
    });
    network.getTransactionHistory(_address).then(function (history) {
      $transaction_history_parent.find('.-spinner-parent').hide();
      $transaction_list_parent.show();
      _transactionHistory = history;
      var counter = 0;
      for (var idx in _transactionHistory) {
        counter++;
        var transaction = _transactionHistory[idx];
        var deltaAssets = '';
        if (transaction.gas_sent) {
          if (transaction.GAS > 0) deltaAssets += '+';
          deltaAssets += (transaction.GAS.toFixed(3) + ' GAS');
        } else {
          if (transaction.NEO > 0) deltaAssets += '+';
          deltaAssets += (transaction.NEO.toFixed(3) + ' NEO');
        }
        $transaction_list.append(`
          <tr>
            <td class='-transaction-block'>` + transaction.block_index + `</td>
            <td class='-transaction-id'><a target='_blank' href=https://neoexplorer.co/transactions/` + transaction.txid + `>` + transaction.txid + `</a></td>
            <td class='-transaction-assets'>` + deltaAssets + `</td>
          </tr>
        `);
        $transaction_list_parent.find('.-view-all-parent').find('a').attr('href', 'https://neoexplorer.co/addresses/' + _address);
      }
    });
  }
  function _initWallet (privateKeyWIF) {
    _privateKey = utils.getPrivateKeyFromWIF(privateKeyWIF);
    _address = utils.getAddressFromPrivateKey(_privateKey);
    console.log("Wallet initialized - address: (" + _address + "), network: (" + network.getNetType() + ")");
    $('.wallet-summary-card').find('.-refresh-button').click(function () {
      $(this).attr('disabled', true);
      _refreshWallet();
    });
    $('.wallet-summary-card').find('.-claim-gas').click(function () {
      transactionProcessModal.display();
      transactionProcessModal.addProgress('Started claiming gas.');
      transactionProcessModal.addProgress('Sending NEO to self.');
      var neoToSelfTransactionHash = null;
      var stateFunctions = {
        successfully_built: function () {
          transactionProcessModal.addProgress('Transaction successfully built.');
        },
        successfully_signed: function () {
          transactionProcessModal.addProgress('Transaction successfully signed. Broadcasting transaction...');
        },
        successfully_returned: function (hash) {
          neoToSelfTransactionHash = hash;
          transactionProcessModal.addProgress(
            'Transaction added to mempool. Transaction hash:<div class=\'-transaction-hash\'><a target=\'_blank\' href=\'https://neoexplorer.co/transactions/' + hash + '\'>' + hash + '</a></div>'
          );
        },
        error_validator_rejected: function () {
          transactionProcessModal.error(
            'Transaction was rejected. Did you recently send a transaction? Wait for the transaction to be confirmed first. Refresh the page and try again.'
          );
        }
      };
      walletCore.doSendAsset(
        _address,
        { ['NEO']: 1 },
        stateFunctions
      ).then(function () {
        transactionProcessModal.addProgress('Waiting for transaction to confirm...');
        _waitForTransactionToConfirm(
          neoToSelfTransactionHash,
          function () {
            transactionProcessModal.addProgress('Transaction confirmed.');
            stateFunctions.successfully_returned = function (hash) {
              transactionProcessModal.addProgress(
                'Transaction added to mempool. Transaction hash:<div class=\'-transaction-hash\'><a target=\'_blank\' href=\'https://neoexplorer.co/transactions/' + hash + '\'>' + hash + '</a></div>'
              );
              transactionProcessModal.complete('Gas will be claimed after the transaction is confirmed.');
            }
            transactionProcessModal.addProgress('Sending Claim Gas transaction.');
            walletCore.doClaimAllGas(stateFunctions).catch(function (reason) {
              transactionProcessModal.error(reason.message);
              console.log(reason);
            });
          },
          function () {
            transactionProcessModal.error('Transaction failed to confirm.');
          }
        );
      }).catch(function (reason) {
        transactionProcessModal.error(reason.message);
        console.log(reason);
      });
    });
    _refreshWallet();
  }
  return {
    doSendAsset: function (to, assetsToSend, stateFunctions) {
      return _doSendAsset(to, _address, assetsToSend, stateFunctions);
    },
    doClaimAllGas: function(stateFunctions) {
      return _doClaimAllGas(_address, stateFunctions);
    },
    getAddress: function () {
      return _address;
    },
    closeWallet: function () {
      _netType = 'MainNet';
      _address = null;
      _privateKey = null;
      _transactionHistory = null;
    },
    initWallet: _initWallet,
    refreshWallet: _refreshWallet
  }
})(utils, components, exclusive, network, balanceManager);

var errorModal = (function () {
  var $_modal = null;
  return {
    setup: function () {
      $_modal = $('#error-modal');
    },
    display: function (title, message) {
      $_modal.find('.modal-header').find('.-text').html(title);
      $_modal.find('.modal-body').find('p').html(message);
      $_modal.modal('show');
    }
  }
})();

var transactionProcessModal = (function () {
  var $_modal = null;
  var $_progressParent = null;
  var $_modalFooter = null;
  function _addProgress(description, error) {
    if (error === undefined) {
      error = false;
    }
    if (error) {
      $_progressParent.append(
        '<div><i class="fa fa-exclamation-circle" aria-hidden="true"></i>' + description + '</div>'
      );
    } else {
      $_progressParent.append(
        '<div><i class="fa fa-check-circle" aria-hidden="true"></i>' + description + '</div>'
      );
    }
  }
  return {
    setup: function () {
      $_modal = $('#transaction-process-modal');
      $_modalFooter = $_modal.find('.modal-footer');
      $_progressParent = $_modal.find('.-progress-parent');
    },
    addProgress: _addProgress,
    complete: function (description) {
      _addProgress(description);
      $_modalFooter.show();
    },
    error: function (description) {
      _addProgress(description, true);
      $_modalFooter.show();
    },
    display: function () {
      $_progressParent.html('');
      $_modalFooter.hide();
      $_modal.modal({
        backdrop: 'static',
        keyboard: false
      });
    },
    close: function () {
      $_modal.modal('hide');
    }
  }
})();

var transactionConfModal = (function (walletCore, errorModal, transactionProcessModal) {
  var $_modal = null;
  var $_confButton = null;
  var _inputs = null;
  return {
    setup: function () {
      $_modal = $('#transaction-conf-modal');
      $_confButton = $_modal.find('.-confirm-button');
      $_confButton.click(function () {
        $_modal.modal('hide');
        transactionProcessModal.display();
        transactionProcessModal.addProgress('Started building transaction.');
        var stateFunctions = {
          successfully_built: function () {
            transactionProcessModal.addProgress('Transaction successfully built.');
          },
          successfully_signed: function () {
            transactionProcessModal.addProgress('Transaction successfully signed. Broadcasting transaction...');
          },
          successfully_returned: function (hash) {
            transactionProcessModal.addProgress(
              'Transaction added to mempool. Transaction hash:<div class=\'-transaction-hash\'><a href=\'https://neoexplorer.co/transactions/' + hash + '\'>' + hash + '</a></div>'
            );
            transactionProcessModal.complete('Transaction should be confirmed in a few minutes and visible in the blockchain.');
          },
          error_validator_rejected: function () {
            transactionProcessModal.error('Transaction was rejected. Did you recently send a transaction? Wait for the transaction to be confirmed first. Refresh the page and try again.');
          }
        };
        walletCore.doSendAsset(
          _inputs.address,
          { [_inputs.mode]: _inputs.number },
          stateFunctions
        ).catch(function (reason) {
          transactionProcessModal.error(reason.message);
          console.log(reason);
        });
        return false;
      });
    },
    display: function (result) {
      _inputs = result.inputs;
      $_modal.find('.-number').html(result.inputs.number);
      $_modal.find('.-asset').html(result.inputs.mode);
      $_modal.find('.-address').html(result.inputs.address);
      $_modal.modal('show');
    }
  }
})(walletCore, errorModal, transactionProcessModal);

var transferAssetForm = (function (utils, transactionConfModal, errorModal) {
  var $_transferAssetForm = null;
  var $_buttonLabel = null;
  var _mode = 'NEO';
  function refreshMenu() {
    $_buttonLabel.html(_mode);
  }
  function _gatherInputs() {
    return {
      mode: _mode,
      address: $_transferAssetForm.find('.-address-input').val(),
      number: $_transferAssetForm.find('.-number-input').val()
    }
  }
  function _validateInputs() {
    var inputs = _gatherInputs();
    if (!utils.isAddress(inputs.address)) {
      return {
        success: false,
        reason: 'That doesn\'t appear to be a NEO address.'
      }
    }
    var regexp = /^-?\d*\.{0,1}\d+$/;
    if (!regexp.test(inputs.number)) {
      return {
        success: false,
        reason: 'Send amount needs to be a number.'
      }
    }
    inputs.number = parseFloat(inputs.number);
    if (inputs.mode === 'NEO') {
      inputs.number = parseInt(inputs.number);
      if (inputs.number <= 0) {
        return {
          success: false,
          reason: 'Cannot send less than 1 NEO.'
        }
      }
    } else {
      if (inputs.number <= 0) {
        return {
          success: false,
          reason: 'Send amount needs to be positive.'
        }
      }
    }
    return {
      success: true,
      inputs: inputs
    }
  }
  return {
    setup: function () {
      $_transferAssetForm = $('.-transfer-asset-form');
      $_buttonLabel = $_transferAssetForm.find('.-amount-input-parent').find('.dropdown-toggle');
      refreshMenu();
      $_transferAssetForm.find('.-amount-input-parent').find('.dropdown-item').click(function () {
        var mode = $(this).data('mode');
        _mode = mode;
        $_buttonLabel.dropdown('toggle');
        refreshMenu();
        return false;
      });
      $_transferAssetForm.submit(function () {
        var result = _validateInputs();
        if (!result.success) {
          errorModal.display('Submit transaction error', result.reason);
        } else {
          transactionConfModal.display(result);
        }
        return false;
      });
    },
    getMode: function () {
      return _mode;
    }
  }
})(utils, transactionConfModal, errorModal);

var UI_MODES = [
  'INTRO',
  'NEW_WALLET',
  'OPEN_WALLET'
];
var UI_MODE_DATA = {};
UI_MODE_DATA[UI_MODES[0]] = { class: 'intro-card', action: 'action-intro', callback: function () {
  walletCore.closeWallet();
} }
UI_MODE_DATA[UI_MODES[1]] = { class: 'new-wallet-card', action: 'action-new-wallet' }
UI_MODE_DATA[UI_MODES[2]] = { class: 'open-wallet-card', action: 'action-open-wallet' }
UI_MODE_DATA[UI_MODES[3]] = { class: 'wallet-summary-card', action: 'action-wallet-summary' }
var ui_mode = UI_MODES[0];

function refresh_ui() {
  $('.-wallet-core-child').hide();
  $('.' + UI_MODE_DATA[ui_mode]['class']).show();
  if (UI_MODE_DATA[ui_mode].callback !== undefined) {
    UI_MODE_DATA[ui_mode].callback();
  }
}

function switch_ui_mode(new_ui_mode) {
  ui_mode = new_ui_mode;
  refresh_ui();
}

function refresh_open_wallet_menu(value) {
  $('.open-wallet-menu').hide();
  if (value === 'private_key') {
    $('.private-key-form').show();
  } else if (value === 'encrypted_private_key') {
    $('.encrypted-private-key-form').show();
  }
}

$(function () {
  window.header_height_margin = $('header').outerHeight() + 24;
  $('body').css('padding-top', window.header_height_margin);
  var $footer = $(".footer");
  if ($footer.length > 0) {
    $footer.css("bottom", -$footer.outerHeight()/2);
    var $main = $("#main-container");
    var original_padding_bottom = parseInt($main.css("padding-bottom"), 10);
    $main.css("padding-bottom", original_padding_bottom + $footer.outerHeight()/2);
    $(window).resize(function() {
      $footer.css("bottom", -$footer.outerHeight()/2);
      var $main = $("#main-container");
      $main.css("padding-bottom", original_padding_bottom + $footer.outerHeight()/2);
    });
  }
  refresh_ui();
  for (var ui_mode in UI_MODE_DATA) {
    $('.' + UI_MODE_DATA[ui_mode]['action']).click((function (ui_mode) {
      return function () {
        switch_ui_mode(ui_mode);
      }
    })(ui_mode));
  }
  transactionProcessModal.setup();
  transactionConfModal.setup();
  errorModal.setup();
  // setup private key form
  $('input[type=radio][name=open_wallet_radio]').change(function() {
    refresh_open_wallet_menu(this.value);
  });
  $('input[type=radio][name=open_wallet_radio][value=encrypted_private_key]').attr('checked', true);
  $('input[type=radio][name=open_wallet_radio][value=encrypted_private_key]').change();
  $('.encrypted-private-key-form').submit(function () {
    var $this = $(this);
    alert($this.find('.-encrypted-private-key-value').val());
    alert($this.find('.-password-value').val());
    return false;
  });
  $('.private-key-form').submit(function () {
    var $this = $(this);
    walletCore.initWallet($this.find('.-private-key-value').val());
    $this.find('.-private-key-value').val('');
    switch_ui_mode(UI_MODES[3]);
    return false;
  });
  // setup transfer asset form
  transferAssetForm.setup();
});