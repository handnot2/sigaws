defmodule Sigaws.Cryto.HMAC do
  @moduledoc false
  def init(type, key), do: :crypto.hmac_init(type, key)
  def update(hmac_ctxt, data), do: :crypto.hmac_update(hmac_ctxt, data)
  def compute(hmac_ctxt), do: :crypto.hmac_final(hmac_ctxt)
end
