defmodule Sigaws.Util do

  @moduledoc """
  A varied collection of functions useful in request signing and verification.
  """

  alias Sigaws.Ctxt
  alias Sigaws.Cryto.Hash
  alias Sigaws.Cryto.HMAC

  @doc """
  Adds given parameters to the given URL's query string.

      iex> "http://a.net/doit?a=10" |> Sigaws.Util.add_params_to_url(%{"b" => "20"})
      "http://a.net/doit?a=10&b=20"

  """
  def add_params_to_url(url, %{} = p) when is_binary(url) do
    uri = URI.parse(url)
    %URI{uri | query: (uri.query || "") |> URI.decode_query(p) |> URI.encode_query()}
    |> URI.to_string()
  end

  @doc """
  Given the verification context checks if the request has expired.

  | Returns | When |
  |:------- |:---- |
  | `:ok`   | `expires_in` is not specified (`nil`) |
  | `:ok`   | `signed_at + expires_in <= utc_now` |
  | `{:error, :expired, ""}` | Otherwise |
  | `{:error, :invalid_data, "timestamp"}` | timestamp is incorrect |

  This can be called from `pre_verification` callback implementation of
  the `Sigaws.Provider` behavior.

  If you need a more nuanced expiration check with clock skew considerations,
  use this implementation as a starting point and have your own expiration
  check called from your `pre_verification` callback implementation.
  """
  @request_expired {:error, :expired, ""}
  @spec check_expiration(Ctxt.t) :: :ok | {:error, atom, binary}
  def check_expiration(%Ctxt{signed_at_amz_dt: signed_at_amz_dt, expires_in: ex}) do
    expired?(parse_amz_dt(signed_at_amz_dt), ex)
  end

  @doc """
  Returns a signing key using `AWS4_HMAC_SHA56` algorithm.

  The verification process relies on the `Sigaws.Provider` behavior to get the
  signing key. This function can be called from this behavior implementation
  to generate the signing key. ([AWS examples](http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html))
  """
  @spec signing_key(Date.t, binary, binary, binary) :: {:ok, binary}
  def signing_key(%Date{} = signed_on, region, service, secret)
      when is_binary(region) and is_binary(service) and is_binary(secret) do
    {:ok,
      "AWS4" <> secret
      |> hmac(signed_on |> Date.to_string() |> String.replace("-", ""))
      |> hmac(region)
      |> hmac(service)
      |> hmac("aws4_request")}
  end

  @doc """
  Converts X-Amz-Date format "YYYMMDDTHHMMSSZ" to Elixir `DateTime` in UTC.

      {:ok, %DateTime{time_zone: "Etc/UTC"}} = parse_amz_dt("20171010T010203Z")

  Returns `{:error, :invalid_data, "timestamp"}` upon error.
  """
  @spec parse_amz_dt(binary) :: {:ok, DateTime.t} | {:error, atom, binary}
  @invalid_timestamp {:error, :invalid_data, "timestamp"}
  def parse_amz_dt(<<
     y::binary-size(4),  m::binary-size(2),  d::binary-size(2), "T",
    hr::binary-size(2), mn::binary-size(2), sc::binary-size(2), "Z">>) do
    "#{y}-#{m}-#{d}T#{hr}:#{mn}:#{sc}Z"
    |> DateTime.from_iso8601()
    |> parsed_utc()
  end
  def parse_amz_dt(_), do: @invalid_timestamp

  @doc false
  @spec amz_dt_now() :: DateTime.t
  def amz_dt_now do
    DateTime.utc_now() |> Map.put(:microsecond, {0, 0})
  end

  @doc false
  @spec amz_dt_iso(DateTime.t) :: binary
  def amz_dt_iso(%DateTime{} = dt) do
    dt |> DateTime.to_iso8601() |> String.replace("-", "") |> String.replace(":", "")
  end

  @doc false
  @spec to_amz_dt(DateTime.t) :: binary
  def to_amz_dt(%DateTime{time_zone: "Etc/UTC"} = dt) do
    dt
    |> Map.put(:microsecond, {0, 0})
    |> DateTime.to_iso8601()
    |> String.replace("-", "")
    |> String.replace(":", "")
  end

  @doc false
  @spec downcase_keys(map) :: map
  def downcase_keys(%{} = map) do
    map |> Enum.map(fn {k, v} -> {String.downcase(k), v} end) |> Enum.into(%{})
  end

  @hash_alg :sha256

  @doc false
  def hmac(key, data) do
    @hash_alg |> HMAC.init(key) |> HMAC.update(data) |> HMAC.compute()
  end

  @doc false
  def hexdigest(data) do
    @hash_alg
    |> Hash.init()
    |> Hash.update(data)
    |> Hash.compute()
    |> Base.encode16(case: :lower)
  end

  @spec expired?({:ok, DateTime.t} | {:error, atom, binary}, integer) ::
      :ok | {:error, atom, binary}
  defp expired?({:ok, %DateTime{time_zone: "Etc/UTC"}}, nil), do: :ok
  defp expired?({:ok, %DateTime{time_zone: "Etc/UTC"} = dt}, ex) do
    now_in_unix = DateTime.utc_now() |> DateTime.to_unix(:seconds)
    expiry_in_unix = DateTime.to_unix(dt, :seconds) + ex
    if expiry_in_unix < now_in_unix, do: @request_expired, else: :ok
  end
  defp expired?({:error, _, _} = error, _), do: error

  defp parsed_utc({:ok, %DateTime{} = dt, _}), do: {:ok, dt}
  defp parsed_utc(_), do: @invalid_timestamp
end
