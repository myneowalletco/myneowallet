Rails.application.routes.draw do
  # static routes
  root to: 'home_page#index'
  post '/neo-wallet-api/sendrawtransaction', to: 'neo_wallet#sendrawtransaction'
  get '/neo-wallet-api/get-balance/:address', to: 'neo_wallet#get_balance'
  get '/neo-wallet-api/get-claims/:address', to: 'neo_wallet#get_claims'
  get '/neo-wallet-api/get-transaction-history/:address', to: 'neo_wallet#get_transaction_history'
  get '/neo-wallet-api/get-transaction/:transaction_id', to: 'neo_wallet#get_transaction'
  get '/neo-wallet-api/get-rpc-endpoint', to: 'neo_wallet#get_rpc_endpoint'
end
