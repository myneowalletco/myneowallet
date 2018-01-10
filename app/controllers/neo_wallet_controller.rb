class NeoWalletController < ApplicationController
  protect_from_forgery with: :null_session

  def get_balance
    response = NeoWalletApi.get_balance(_get_net_type, params[:address])
    render json: response
  end

  def get_claims
    response = NeoWalletApi.get_claims(_get_net_type, params[:address])
    render json: response
  end

  def get_transaction_history
    response = NeoWalletApi.get_transaction_history(_get_net_type, params[:address])
    render json: response
  end

  def get_transaction
    begin
      response = NeoWalletApi.get_transaction(_get_net_type, params[:transaction_id])
    rescue => code
      render json: {}, status: code.message
      return
    end
    render json: response
  end

  def get_rpc_endpoint
    response = NeoWalletApi.get_rpc_endpoint(_get_net_type)
    render json: response
  end

  def sendrawtransaction
    rpc_endpoint = NeoWalletApi.get_rpc_endpoint(_get_net_type)['node']
    response = NeoWalletApi.send_raw_transaction(rpc_endpoint, params)
    render json: response
  end

  private

  def _get_net_type
    if params.has_key?(:net_type)
      if params[:net_type] == 'MainNet'
        return :main_net
      elsif params[:net_type] == 'TestNet'
        return :test_net
      else
        return false
      end
    end
    return :main_net
  end
end