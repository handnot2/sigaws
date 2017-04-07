defmodule Sigaws.Cryto.Hash do
  @moduledoc false
  def init(type), do: :crypto.hash_init(type)
  def update(hash_ctxt, data), do: :crypto.hash_update(hash_ctxt, data)
  def compute(hash_ctxt), do: :crypto.hash_final(hash_ctxt)
end
