function Balance(bal) {
  this.address = bal.address;
  this.net = bal.net;
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

var utils = (function () {
  var _BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  var _base58 = module.baseX(_BASE58);
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
  function _getScriptHashFromAddress(address) {
    var hash = ab2hexstring(_base58.decode(address));
    return reverseHex(hash.substr(2, 40));
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
  return {
    getPrivateKeyFromWIF: _getPrivateKeyFromWIF,
    getAddressFromPrivateKey: _getAddressFromPrivateKey,
    getVerificationScriptFromPublicKey: _getVerificationScriptFromPublicKey,
    getPublicKeyFromPrivateKey: _getPublicKeyFromPrivateKey,
    isPrivateKey: _isPrivateKey,
    getScriptHashFromAddress: _getScriptHashFromAddress,
    base58: _base58
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
      var bal = new Balance({ _netType, address: res.data.address });
      Object.keys(res.data).map(function(key) {
        if (key === 'net' || key === 'address') return;
        var parsedAsset = {
          balance: +(res.data[key].balance).toFixed(8),
          unspent: res.data[key].unspent.map(function(coin) {
            coin.value = +(coin.value).toFixed(8)
            return coin
          })
        }
        bal.addAsset(key, parsedAsset);
      });
      Object.assign(bal, res.data);
      return bal;
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
  var _serializeExclusive = {}
  _serializeExclusive[2] = _serializeClaimExclusive;
  _serializeExclusive[128] = _serializeContractExclusive;
  _serializeExclusive[209] = _serializeInvocationExclusive;
  return {
    serializeExclusive: _serializeExclusive
  }
})(components);

var walletCore = (function (utils, components, exclusive, network) {
  var _netType = 'MainNet';
  var _address = null;
  var _privateKey = null;
  var _ASSETS = {
    NEO: 'NEO',
    'c56f33fc6ecfcd0c225c4ab356fee59390af8560be0e930faebe74a6daff7c9b': 'NEO',
    GAS: 'GAS',
    '602c79718b16e442de58778e148d0b1084e3b2dffd5de6b7b16cee7969282de7': 'GAS'
  };
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
      var assetSymbol = _ASSETS[assetId];
      if (balances.assetSymbols.indexOf(assetSymbol) === -1) {
        throw new Error('This balance does not contain any ' + assetSymbol + '!');
      }
      var assetBalance = balances.assets[assetSymbol];
      if (assetBalance.balance * 100000000 < requiredAmt) {
        throw new Error('Insufficient ' + _ASSETS[assetId] + '! Need ' + (requiredAmt / 100000000) + ' but only found ' + assetBalance.balance);
      }
      // Ascending order sort
      assetBalance.unspent.sort(function(a, b) { return a.value - b.value });
      var selectedInputs = 0;
      var selectedAmt = 0;
      // Selected min inputs to satisfy outputs
      while (selectedAmt < requiredAmt) {
        selectedInputs += 1;
        if (selectedInputs > assetBalance.unspent.length) {
          throw new Error('Insufficient ' + ASSETS[assetId] + '! Reached end of unspent coins!');
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
    }, config)
    this.type = tx.type;
    this.version = tx.version;
    this.attributes = tx.attributes;
    this.inputs = tx.inputs;
    this.outputs = tx.outputs;
    this.calculate = function (balances) {
      var result = _calculateInputs(balances, this.outputs, this.gas);
      this.inputs = result.inputs;
      this.outputs = this.outputs.concat(result.change);
      return this;
    }
    this.sign = function(privateKey) {
      return _signTransaction(this, privateKey);
    }
  }
  Transaction.createContractTx = function(balances, intents, override = {}) {
    if (intents === null) throw new Error('Useless transaction!');
    var txConfig = Object.assign({
      type: 128,
      version: _TX_VERSION.CONTRACT,
      outputs: intents
    }, override);
    return new Transaction(txConfig).calculate(balances);
  }
  function _doSendAsset(to, from, assetsToSend) {
    var intents = Object.keys(assetsToSend).map(function (key) {
      return {
        assetId: _ASSET_ID[key],
        value: assetsToSend[key],
        scriptHash: utils.getScriptHashFromAddress(to)
      }
    });
    var signedTx = null;
    var endPoint = null;
    return Promise.all([network.getRPCEndpoint(), network.getBalance(_address)]).then(function (values) {
      endPoint = values[0];
      var balance = values[1];
      var unsignedTx = Transaction.createContractTx(balance, intents);
      return unsignedTx.sign(_privateKey);
    }).then(function (signedResult) {
      signedTx = signedResult;
      return network.sendRawTransaction(components.serializeTransaction(signedTx)).execute(endPoint);
    }).then(function (res) {
      if (res.result === true) {
        res.txid = signedTx.hash;
      }
      return res;
    });
  }
  var _refreshDisabledCounter = 2;
  function _refreshWallet() {
    if (_refreshDisabledCounter < 2) {
      return;
    }
    _refreshDisabledCounter = 0;
    var $wallet_summary_card = $('.wallet-summary-card');
    $wallet_summary_card.find('.-wallet-address').find('.-wallet-address-text').html(_address);
    $wallet_summary_card.find('.-neo-balance').find('.-value').html('...');
    $wallet_summary_card.find('.-gas-balance').find('.-value').html('...');
    $wallet_summary_card.find('.-claim-gas').find('.-value').html('...');
    network.getBalance(_address).then(function (balance) {
      _refreshDisabledCounter += 1;
      if (_refreshDisabledCounter == 2) {
        $wallet_summary_card.find('.-refresh-button').removeAttr("disabled");
      }
      $wallet_summary_card.find('.-neo-balance').find('.-value').html(balance.assets['NEO']['balance']);
      $wallet_summary_card.find('.-gas-balance').find('.-value').html(balance.assets['GAS']['balance']);
    });
    network.getClaims(_address).then(function (claims) {
      _refreshDisabledCounter += 1;
      if (_refreshDisabledCounter == 2) {
        $wallet_summary_card.find('.-refresh-button').removeAttr("disabled");
      }
      $wallet_summary_card.find('.-claim-gas').find('.-value').html(claims.total_claim);
    });
  }
  // https://github.com/neotracker/neotracker-wallet/blob/6c612de7f38c80689260112cb271804f063a6b1c/src/wallet/shared/neon/index.js
  return {
    doSendAsset: function (to, assetsToSend) {
      _doSendAsset(to, _address, assetsToSend);
    },
    getAddress: function () {
      return _address;
    },
    initWallet: function (privateKeyWIF) {
      _privateKey = utils.getPrivateKeyFromWIF(privateKeyWIF);
      _address = utils.getAddressFromPrivateKey(_privateKey);
      console.log("Wallet initialized - address: (" + _address + ")");
      $('.wallet-summary-card').find('.-refresh-button').click(function () {
        $(this).attr('disabled', true);
        _refreshWallet();
      });
      _refreshWallet();
    },
    refreshWallet: _refreshWallet
  }
})(utils, components, exclusive, network);

var UI_MODES = [
  'INTRO',
  'NEW_WALLET',
  'OPEN_WALLET'
];
var UI_MODE_DATA = {};
UI_MODE_DATA[UI_MODES[0]] = { class: 'intro-card', action: 'action-intro' }
UI_MODE_DATA[UI_MODES[1]] = { class: 'new-wallet-card', action: 'action-new-wallet' }
UI_MODE_DATA[UI_MODES[2]] = { class: 'open-wallet-card', action: 'action-open-wallet' }
UI_MODE_DATA[UI_MODES[3]] = { class: 'wallet-summary-card', action: 'action-wallet-summary' }
var ui_mode = UI_MODES[0];

function refresh_ui() {
  $('.-wallet-core-child').hide();
  $('.' + UI_MODE_DATA[ui_mode]['class']).show();
}

function switch_ui_mode(new_ui_mode) {
  ui_mode = new_ui_mode;
  refresh_ui();
}

function refresh_open_wallet_menu(value) {
  $('.open-wallet-menu').hide();
  if (value === 'private_key') {
    $('.private-key-form').show();
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
  $('input[type=radio][name=open_wallet_radio]').change(function() {
    refresh_open_wallet_menu(this.value);
  });
  $('input[type=radio][name=open_wallet_radio][value=private_key]').attr('checked', true);
  $('input[type=radio][name=open_wallet_radio][value=private_key]').change();
  $('.private-key-form').submit(function () {
    var $this = $(this);
    walletCore.initWallet($this.find('.-private-key-value').val());
    $this.find('.-private-key-value').val('');
    switch_ui_mode(UI_MODES[3]);
    return false;
  });
});