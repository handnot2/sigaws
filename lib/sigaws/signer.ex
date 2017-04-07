defmodule Sigaws.Signer do
  @moduledoc false

  alias Sigaws.Util

  @aws_alg  "AWS4-HMAC-SHA256"

  @spec sign_req(map) :: {:ok, map, map} | {:error, atom, binary}
  def sign_req(%{req_path: req_path, method: method,
      params: params, headers: headers, body: body,
      signed_at: signed_at_amz_dt,
      region: region, service: service,
      access_key: ak, signing_key: signing_key}) do

    [date, _] = String.split(signed_at_amz_dt, "T")
    cred_scope = "#{date}/#{region}/#{service}/aws4_request"
    credential = "#{ak}/#{cred_scope}"

    payload_hash = payload_hash(body)

    headers = headers |> Map.put("x-amz-date", signed_at_amz_dt)
    headers_to_sign = headers |> Map.keys() |> Enum.sort() |> Enum.join(";")
    params_to_sign = params

    c_qs = c_qs(params_to_sign)
    c_headers = c_headers(headers)
    c_req = c_req(method, req_path, c_qs, c_headers, headers_to_sign, payload_hash)
    sts = sts(@aws_alg, signed_at_amz_dt, cred_scope, c_req)
    signature = signing_key |> signature(sts)

    authz_header = [
      @aws_alg, " ",
      "Credential=", credential, ", ",
      "SignedHeaders=", headers_to_sign, ", ",
      "Signature=", signature
    ]

    sig_data = %{
      "X-Amz-Algorithm"     => "AWS4-HMAC-SHA256",
      "X-Amz-Date"          => signed_at_amz_dt,
      "X-Amz-SignedHeaders" => headers_to_sign,
      "Authorization"       => authz_header |> IO.iodata_to_binary(),
    }

    extra = if Mix.env != :prod, do: %{c_req: c_req, sts: sts}, else: %{}

    {:ok, Map.put(sig_data, "X-Amz-Content-Sha256", payload_hash), extra}
  end

  @spec sign_url(map) :: {:ok, map, map} | {:error, atom, binary}
  def sign_url(%{req_path: req_path, method: method,
      params: params, headers: headers, body: body,
      signed_at: signed_at_amz_dt,
      region: region, service: service,
      access_key: ak, signing_key: signing_key}) do

    [date, _] = String.split(signed_at_amz_dt, "T")
    cred_scope = "#{date}/#{region}/#{service}/aws4_request"
    credential = "#{ak}/#{cred_scope}"

    payload_hash = payload_hash(body)

    headers_to_sign = headers |> Map.keys() |> Enum.sort() |> Enum.join(";")

    sig_data = %{
      "X-Amz-Algorithm"     => @aws_alg,
      "X-Amz-Credential"    => credential,
      "X-Amz-Date"          => signed_at_amz_dt,
      "X-Amz-SignedHeaders" => headers_to_sign,
    }

    params_to_sign = params |> Map.merge(sig_data)

    c_qs = c_qs(params_to_sign)
    c_headers = c_headers(headers)
    c_req = c_req(method, req_path, c_qs, c_headers, headers_to_sign, payload_hash)
    sts = sts(@aws_alg, signed_at_amz_dt, cred_scope, c_req)
    signature = signing_key |> signature(sts)

    sig_data =
      sig_data
      |> Map.put("X-Amz-Signature", signature)
      |> Map.put("X-Amz-Content-Sha256", payload_hash)

    extra = if Mix.env != :prod, do: %{c_req: c_req, sts: sts}, else: %{}
    {:ok, sig_data, extra}
  end

  def c_qs(%{} = params) do
    params |> URI.encode_query() |> String.replace("+", "%20")
  end

  defp normalize_header_name(k) when is_binary(k) do
    k |> String.trim() |> String.downcase()
  end

  @ws_re ~r/\s+/
  defp normalize_header_value(v) when is_binary(v) do
    Regex.replace(@ws_re, String.trim(v), " ")
  end
  defp normalize_header_value(v) when is_list(v) do
    v
    |> List.foldr([], fn
        i, []  -> [normalize_header_value(i)]
        i, acc -> [normalize_header_value(i), ",", acc]
       end)
  end

  defp c_headers(%{} = headers) do
    headers
    |> Enum.map(fn {k, v} ->
        {normalize_header_name(k), normalize_header_value(v)}
       end)
    |> Enum.sort(&(&1 < &2))
    |> Enum.map(fn {k, v} -> [k, ":", v, "\n"] end)
  end

  defp c_req(m, p, c_qs, c_headers, headers_to_sign, payload_hash) do
    [m, "\n", URI.encode(p), "\n", c_qs, "\n", c_headers, "\n",
     headers_to_sign, "\n", payload_hash]
  end

  defp sts(alg, signed_at_amz_dt, cred_scope, c_req) do
    [alg, "\n", signed_at_amz_dt, "\n", cred_scope, "\n", c_req |> Util.hexdigest()]
  end

  defp signature(signing_key, sts) do
    signing_key |> Util.hmac(sts) |> Base.encode16(case: :lower)
  end

  @empty_str_hash "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  defp payload_hash(nil), do: @empty_str_hash
  defp payload_hash(""), do: @empty_str_hash
  defp payload_hash(:unsigned), do: "UNSIGNED-PAYLOAD"
  defp payload_hash(payload), do: payload |> Util.hexdigest()
end
