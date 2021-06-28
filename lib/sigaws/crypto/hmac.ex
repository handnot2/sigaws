defmodule Sigaws.Crypto.HMAC do
  @moduledoc false

  if System.otp_release() |> String.to_integer() < 24 do
    def init(type, key), do: :crypto.hmac_init(type, key)
    def update(hmac_ctxt, data), do: :crypto.hmac_update(hmac_ctxt, data)
    def compute(hmac_ctxt), do: :crypto.hmac_final(hmac_ctxt)
  else
    def init(type, key), do: :crypto.mac_init(:hmac, type, key)
    def update(hmac_ctxt, data), do: :crypto.mac_update(hmac_ctxt, data)
    def compute(hmac_ctxt), do: :crypto.mac_final(hmac_ctxt)
  end
end
