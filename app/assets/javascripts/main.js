var walletCore = (function () {
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
  var BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  var base58 = module.baseX(BASE58);
  function _dec2hex (dec) {
    return ('0' + dec.toString(16)).substr(-2)
  }
  function _reverseHex(hex) {
    if (typeof hex !== 'string') throw new Error('reverseHex expects a string');
    if (hex.length % 2 !== 0) throw new Error('Incorrect Length: ' + hex);
    var out = '';
    for (let i = hex.length - 2; i >= 0; i -= 2) {
      out += hex.substr(i, 2)
    }
    return out;
  }
  function _getScriptHashFromAddress(address) {
    var hash = ab2hexstring(base58.decode(address));
    return _reverseHex(hash.substr(2, 40));
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
          scriptHash: _getScriptHashFromAddress(balances.address)
        })
      }
      // Format inputs
      return assetBalance.unspent.slice(0, selectedInputs).map(function(input) {
        return { prevHash: input.txid, prevIndex: input.index }
      });
    }).reduce(function(prev, curr) { prev.concat(curr), [] });
    return { inputs: inputs, change: change };
  }
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
  }
  function createContractTx(balances, intents, override = {}) {
    if (intents === null) throw new Error('Useless transaction!');
    var txConfig = Object.assign({
      type: 128,
      version: _TX_VERSION.CONTRACT,
      outputs: intents
    }, override);
    return new Transaction(txConfig).calculate(balances);
  }
  function getAPIEndpoint(net) {
    switch(net) {
      case 'MainNet':
        return 'http://api.wallet.cityofzion.io'
      case 'TestNet':
        return 'http://testnet-api.wallet.cityofzion.io'
      default:
        return net
    }
  }
  function getBalance() {
    var apiEndpoint = getAPIEndpoint(_netType);
    return axios.get(apiEndpoint + '/v2/address/balance/' + _address).then(function(res) {
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
  function getClaims() {
    var apiEndpoint = getAPIEndpoint(_netType);
    return axios.get(apiEndpoint + '/v2/address/claims/' + _address).then(function(res) {
      return res.data
    });
  }
  function getRPCEndpoint() {
    var apiEndpoint = getAPIEndpoint(_netType);
    return axios.get(apiEndpoint + '/v2/network/best_node').then(function(response) {
      return response.data.node
    });
  }
  function getTransactionHistory() {
    var apiEndpoint = getAPIEndpoint(_netType);
    return axios.get(apiEndpoint + '/v2/address/history/' + _address).then(function(response) {
      return response.data.history
    });
  }
  function doSendAsset(to, from, assetsToSend) {
    var intents = Object.keys(assetsToSend).map(function (key) {
      return {
        assetId: _ASSET_ID[key],
        value: assetsToSend[key],
        scriptHash: _getScriptHashFromAddress(to)
      }
    });
    return Promise.all([getRPCEndpoint(), getBalance()]).then(function (values) {
      var endPoint = values[0];
      var balance = values[1];
      var unsignedTx = createContractTx(balance, intents);
      console.log(unsignedTx);
    });
  }
  // https://github.com/neotracker/neotracker-wallet/blob/6c612de7f38c80689260112cb271804f063a6b1c/src/wallet/shared/neon/index.js
  function _getPublicKey(privateKey, encode) {
    var ecparams = module.ecurve.getCurveByName('secp256r1');
    var curvePt = ecparams.G.multiply(module.BigInteger.fromBuffer(hexstring2ab(privateKey)));
    return curvePt.getEncoded(encode);
  }
  function _getHash(signatureScript) {
    var programHexString = module.CryptoJS.enc.Hex.parse(signatureScript);
    var programSha256 = module.CryptoJS.SHA256(programHexString);
    return module.CryptoJS.RIPEMD160(programSha256);
  }
  function _createSignatureScript(publicKeyEncoded) {
    return "21" + publicKeyEncoded.toString('hex') + "ac";
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

    return base58.encode(datas);
  }
  function getAddressFromPrivateKey() {
    var accounts = [];
    var publicKeyEncoded = _getPublicKey(_privateKey, true);
    var publicKeyHash = _getHash(publicKeyEncoded.toString('hex'));
    var script = _createSignatureScript(publicKeyEncoded);
    var programHash = _getHash(script);
    var address = _toAddress(hexstring2ab(programHash.toString()));
    return address;
  }
  function _getPrivateKeyFromWIF(privateKeyWIF) {
    var data = base58.decode(privateKeyWIF);
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
  return {
    getAPIEndpoint: getAPIEndpoint,
    getBalance: getBalance,
    getClaims: getClaims,
    getRPCEndpoint: getRPCEndpoint,
    getTransactionHistory: getTransactionHistory,
    doSendAsset: doSendAsset,
    setNetType: function (net) {
      _netType = net;
    },
    getNetType: function () {
      return _netType;
    },
    getAddress: function () {
      return _address;
    },
    initWallet: function (privateKeyWIF) {
      _privateKey = _getPrivateKeyFromWIF(privateKeyWIF);
      _address = getAddressFromPrivateKey();
      console.log("Wallet initialized - address: (" + _address + ")");
      var $wallet_summary_card = $('.wallet-summary-card');
      $wallet_summary_card.find('.-wallet-address').find('.-wallet-address-text').html(_address);
      getBalance().then(function (balance) {
        $wallet_summary_card.find('.-neo-balance').find('.-value').html(balance.assets['NEO']['balance']);
        $wallet_summary_card.find('.-gas-balance').find('.-value').html(balance.assets['GAS']['balance']);
      });
      getClaims().then(function (claims) {
        $wallet_summary_card.find('.-claim-gas').find('.-value').html(claims.total_claim);
      });
    }
  }
})();

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