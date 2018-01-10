require "net/http"

module NeoWalletApi
  GET_API_ENDPOINT = {
    main_net: 'http://api.wallet.cityofzion.io/',
    test_net: 'http://testnet-api.wallet.cityofzion.io/'
  }

  ENDPOINT_SUFFIX = {
    get_balance: 'v2/address/balance/',
    get_claims: 'v2/address/claims/',
    get_rpc_endpoint: 'v2/network/best_node',
    get_transaction_history: 'v2/address/history/',
    get_transaction: 'v2/transaction/'
  }

  def self.get_json_response_and_parse(uri)
    uri = URI.parse(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    response = http.get(uri.request_uri)
    if response.code != '200'
      raise response.code.to_s
    end
    return ActiveSupport::JSON.decode(response.body)
  end

  def self.post_json_response_and_parse(uri, params)
    uri = URI.parse(uri)
    http = Net::HTTP.new(uri.host, uri.port)
    request = Net::HTTP::Post.new(uri.request_uri, { 'Content-Type': 'application/json' })
    request.body = params.to_json
    response = http.request(request)
    return ActiveSupport::JSON.decode(response.body)
  end

  def self.get_balance(net_type, address)
    get_json_response_and_parse(GET_API_ENDPOINT[net_type.to_sym] + \
      ENDPOINT_SUFFIX[:get_balance] + \
      address)
  end

  def self.get_claims(net_type, address)
    get_json_response_and_parse(GET_API_ENDPOINT[net_type.to_sym] + \
      ENDPOINT_SUFFIX[:get_claims] + \
      address)
  end

  def self.get_rpc_endpoint(net_type)
    get_json_response_and_parse(GET_API_ENDPOINT[net_type.to_sym] + \
      ENDPOINT_SUFFIX[:get_rpc_endpoint])
  end

  def self.get_transaction_history(net_type, address)
    get_json_response_and_parse(GET_API_ENDPOINT[net_type.to_sym] + \
      ENDPOINT_SUFFIX[:get_transaction_history] + \
      address)
  end

  def self.get_transaction(net_type, transaction_id)
    get_json_response_and_parse(GET_API_ENDPOINT[net_type.to_sym] + \
      ENDPOINT_SUFFIX[:get_transaction] + \
      transaction_id)
  end

  def self.send_raw_transaction(uri, params)
    post_json_response_and_parse(uri, params)
  end
end
