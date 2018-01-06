var walletCore = (function () {
  var _netType = 'MainNet';
  var _address = null;
  var _privateKey = null;
  var _privateKeyBytes = [];
  function _dec2hex (dec) {
    return ('0' + dec.toString(16)).substr(-2)
  }
  function _generatePrivateKeyBytes() {
    var crypto_lib = window.crypto || window.msCrypto; // for IE 11
    var arr = new Uint8Array(32);
    crypto_lib.getRandomValues(arr);
    for (var i = 0; i < arr.length; ++i) {
      _privateKeyBytes[i] = arr[i];
    }
    _privateKey = Array.from(arr, _dec2hex).join('');
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
      return res.data;
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
  var BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  var base58 = module.baseX(BASE58);
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
        $wallet_summary_card.find('.-neo-balance').find('.-value').html(balance['NEO']['balance']);
        $wallet_summary_card.find('.-gas-balance').find('.-value').html(balance['GAS']['balance']);
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