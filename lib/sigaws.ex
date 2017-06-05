defmodule Sigaws do
  @moduledoc """
  A library to sign and verify HTTP requests using AWS Signature V4.

  [![Inline docs](http://inch-ci.org/github/handnot2/sigaws.svg)](http://inch-ci.org/github/handnot2/sigaws)

  `Sigaws` does not dictate how you compose and send HTTP requests. You can use
  `HTTPoison` or any other HTTP client to do that. The signing functions in this
  library work with the HTTP request information provided and return an
  Elixir map containing signature related parameters/headers. Similarly,
  the verification works with the request information and a provider to
  perform verification.
  
  Take look at `plug_sigaws`, a plug built using this library. This plug can be
  added to your API pipeline to protect your API endpoints. It can also be added
  to browser pipelines to protect access to web resources using "presigned"
  URLs with access expiration.

  ### Examples

  #### Signature to be passed as request headers

      url = "http://api.endpoint.host:5000/somthing?a=10&b=20"
      headers = %{"header1" => "value1", "header2" => "value2"}
      {:ok, %{} = sig_data, _} =
        Sigaws.sign_req(url,
                        headers: headers,
                        region: "delta-quad",
                        service: "my-service",
                        access_key: "some-access-key",
                        secret: "some-secret")

      {:ok, resp} = HTTPoison.get(url, Map.merge(headers, sig_data))
  
  #### Signature to be passed in query string ("presigned" URL)

      url = "http://api.endpoint.host:5000/somthing?a=10&b=20"
      {:ok, %{} = sig_data, _} =
        Sigaws.sign_url(url,
                        body: :unsigned,
                        expires_in: 5 * 60,                 # 5 minutes
                        region: "delta-quad",
                        service: "my-service",
                        access_key: "some-access-key",
                        secret: "some-secret")

      presigned_url = Sigaws.Util.add_params_to_url(url, sig_data)

  #### Signature Verification

  The verification process relies on a provider module that implements
  `Sigaws.Provider` behavior. The provider is expected to supply the signing
  key based on the information present in the context (primarily the access key).

      {:ok, %Sigaws.Ctxt{} = ctxt} =
        Sigaws.Verify(conn.request_path,
          method: conn.method,
          params: conn.query_params,
          headers: conn.req_headers,
          body: get_raw_body(conn),
          provider: SigawsQuickStartProvider)

  Checkout this
  [Blog post](https://handnot2.github.io/blog/elixir/aws-signature-sigaws)
  that shows how to protect Phoenix built REST APIs using `plug_sigaws` and
  `sigaws_quickstart_provider` Hex packages.
  """

  alias Sigaws.Ctxt
  alias Sigaws.Signer
  alias Sigaws.Verifier
  alias Sigaws.Util

  @doc """
  Sign the given HTTP request and return the signature data to be treated as request headers.

  | Name | Description |
  |:------ |:----------- |
  | `:method` | A string value -- `GET`, `POST`, `PUT`, etc (defaults to `GET`) |
  | `:params`<br/>&nbsp; | A map of query parameters -- merged with the query string in the given url (defaults to an empty map) |
  | `:headers` | A map of request headers (defaults to an empty map) |
  | `:body`<br/>&nbsp; | A string value (use appropriate encoder) or `:unsigned` or `{:content_hash, hash}` (defaults to an empty string) |
  | `:signed_at`<br/>&nbsp; | `DateTime` in UTC or a string in the form `YYYMMDDTHHmmSSZ` (defults to current time in UTC) |
  | `:expires_in` | Optional expiration in seconds since the signing time |
  | `:region` | A string value |
  | `:service` | A string value |
  | `:access_key`<br/>&nbsp; | Access key ID used for signing (defaults to `AWS_ACCESS_KEY_ID` environment variable) |
  | `:signing_key` | A signing key can be provided instead of a secret key |
  | `:secret`<br/>&nbsp; | Used when signing key is not provided (defaults to `AWS_SECRET_ACCESS_KEY` environment variable) |

  When there are no errors in signing, this function returns: `{:ok, sig_data, info}`
  The signature data returned in `sig_data` map include the following:

  * `X-Amz-Algorithm`
  * `X-Amz-Date`
  * `X-Amz-SignedHeaders`
  * `Authorization`

  The third item `info` is also a map. When the MIX environment is either `:dev`
  or `:test`, this info map contains the canonical request (`c_req`) and the
  string to sign (`sts`) computed during the signature generation. In all other
  MIX environments (including `:prod`) this info will be an empty map.

  | Error Returns |
  |:------------- |
  | `{:error, :invalid_input, _}` |
  | `{:error, :invalid_data, _}` |

  """
  @spec sign_req(binary, keyword) :: {:ok, map, map} | {:error, atom, binary}
  def sign_req(url, additional_named_input) when is_list(additional_named_input) do
    with {:ok, vinput} <- validate_signing_input(url, additional_named_input)
    do
      Signer.sign_req(vinput)
    end
  end

  @doc """
  Presign the given URL and return the signature data to be treated as query parameters.

  Refer to `sign_req/2` for the named input that can be passed along with the URL.
  The returned `sig_data` should be merged with any existing query parameters in
  the URL while sending the request to the server. (Checkout the examples
  at the top.)

  When there are no errors in signing, this function returns: `{:ok, sig_data, info}`
  The `sig_data` map returned includes the following query parameters:

  * `X-Amz-Algorithm`
  * `X-Amz-Content-Sha256`
  * `X-Amz-Credential`
  * `X-Amz-Date`
  * `X-Amz-SignedHeaders`
  * `X-Amz-Signature`

  """
  @spec sign_url(binary, keyword) :: {:ok, map, map} | {:error, atom, binary}
  def sign_url(url, additional_named_input) when is_list(additional_named_input) do
    with {:ok, vinput} <- validate_signing_input(url, additional_named_input)
    do
      Signer.sign_url(vinput)
    end
  end

  @doc """
  Verify the signature of the given HTTP request data.

  The request data passed should include the signature information either in
  query parameters (presigned request) or in the request headers. Presence of
  `X-Amz-Credential` or `X-Amz-Signature` in the query parameters leads to
  treatment of the request as a "presigned" request. If not, the signature
  data are expected to be in the `Authorization` and other headers.

  | Name | Description |
  |:------ |:----------- |
  | `:method` | Optional string value -- `GET`, `POST`, `PUT`, etc (defaults to `GET`) |
  | `:query_string` | Optional string value (defaults to empty string) |
  | `:params` | Optinal query parameters (defaults to empty map) |
  | `:headers` | Optional request headers (defaults to empty map) |
  | `:body`<br/>&nbsp; | Optional raw body -- not decoded values such as JSON (defaults to empty string) |
  | `:provider` | Module that implements `Sigaws.Provider` behavior -- required |

  Upon successful signature verification this function returns `{:ok, %Sigaws.Ctxt{} = ctxt}`. The returned context `Sigaws.Ctx` can be used to make further policy
  decisions if desired.

  | Error Returns |
  |:------------- |
  | `{:error, :invalid_input, _}` |
  | `{:error, :invalid_data, _}` |
  | `{:error, :missing_data, _}` |
  | `{:error, :verification_failed, ""}` |
  | `{:error, :mismatched, "X-Amz-Date"}` |

  """
  @spec verify(binary, keyword) :: {:ok, Ctxt.t} | {:error, atom, binary}
  def verify(req_path, opts) do
    opts_map = Map.new(opts)
    with {:ok, provider}  <- provider_opt(opts_map),
         {:ok, method}    <- method_opt(opts_map),
         {:ok, qs}        <- qs_opt(opts_map),
         {:ok, params}    <- qp_opt(opts_map),
         {:ok, headers}   <- headers_opt(opts_map),
         {:ok, body}      <- body_opt(opts_map)
    do
      params = qs |> URI.decode_query() |> Map.merge(params)
      headers = headers |> Util.downcase_keys()
      validated_opts = %{
        method: method, params: params, headers: headers, body: body,
        provider: provider
      }
      if Verifier.presigned?(params) do
        Verifier.verify_url(req_path, validated_opts)
      else
        Verifier.verify_req(req_path, validated_opts)
      end
    else
      _error ->
        {:error, :verification_failed, "Signature verification failed"}
    end
  end

  @spec validate_signing_input(binary, keyword) ::
      {:ok, map} | {:error, atom, binary}
  defp validate_signing_input(url, opts) do
    with opts_map = Map.new(opts),
         {:ok, method}           <- method_opt(opts_map),
         {:ok, params}           <- qp_opt(opts_map),
         {:ok, headers}          <- headers_opt(opts_map),
         {:ok, body}             <- body_opt(opts_map),
         {:ok, signed_at_amz_dt} <- signed_at_opt(opts_map),
         {:ok, dt}               <- Util.parse_amz_dt(signed_at_amz_dt),
         {:ok, rg}               <- region_opt(opts_map),
         {:ok, sv}               <- service_opt(opts_map),
         {:ok, creds}            <- creds_opts(opts_map)
    do
      %URI{path: req_path, query: qs} = uri = URI.parse(url)
      req_path = if req_path, do: req_path, else: "/"

      params = (qs || "") |> URI.decode_query() |> Map.merge(params)
      headers = headers |> Util.downcase_keys() |> Map.put_new("host", uri_host(uri))

      signing_key = case creds do
        %{secret: secret} ->
          {:ok, key} = dt |> DateTime.to_date() |> Util.signing_key(rg, sv, secret)
          key
        %{signing_key: key} -> key
      end

      {:ok, %{req_path: req_path, method: method,
              params: params, headers: headers, body: body,
              signed_at: signed_at_amz_dt, region: rg, service: sv,
              access_key: creds[:access_key], signing_key: signing_key}}
    end
  end

  defp uri_host(%URI{scheme: "https", host: h, port: 443}), do: h
  defp uri_host(%URI{scheme: "http",  host: h, port: 80}), do: h
  defp uri_host(%URI{host: nil}), do: ""
  defp uri_host(%URI{host: h, port: nil}), do: h
  defp uri_host(%URI{host: h, port: p}), do: "#{h}:#{p}"

  @http_methods ["GET", "PUT", "POST", "PATCH", "DELETE", "HEAD", "OPTIONS"]
  @method_error {:error, :invalid_input, "method"}
  defp method_opt(%{method: m}) when is_binary(m) do
    v = String.upcase(m)
    if v in @http_methods, do: {:ok, v}, else: @method_error
  end
  defp method_opt(%{method: _}), do: @method_error
  defp method_opt(_), do: {:ok, "GET"}

  @qs_error {:error, :invalid_input, "query_string"}
  defp qs_opt(%{query_string: nil}), do: {:ok, ""}
  defp qs_opt(%{query_string: q}) when is_binary(q), do: {:ok, q}
  defp qs_opt(%{query_string: _}), do: @qs_error
  defp qs_opt(_), do: {:ok, ""}

  @qp_error {:error, :invalid_input, "params"}
  defp qp_opt(%{params: %{} = p}), do: {:ok, p}
  defp qp_opt(%{params: p}) when is_list(p), do: {:ok, list_to_map(p)}
  defp qp_opt(%{params: _}), do: @qp_error
  defp qp_opt(_), do: {:ok, %{}}

  @headers_error {:error, :invalid_input, "headers"}
  defp headers_opt(%{headers: %{} = h}), do: {:ok, h}
  defp headers_opt(%{headers: h}) when is_list(h), do: {:ok, list_to_map(h)}
  defp headers_opt(%{headers: _}), do: @headers_error
  defp headers_opt(_), do: {:ok, %{}}

  @body_error {:error, :invalid_input, "body"}
  defp body_opt(%{body: :unsigned}), do: {:ok, :unsigned}
  defp body_opt(%{body: {:content_hash, hash}}), do: {:ok, {:content_hash, hash}}
  defp body_opt(%{body: b}) when is_binary(b), do: {:ok, b}
  defp body_opt(%{body: _}), do: @body_error
  defp body_opt(_), do: {:ok, ""}

  @spec signed_at_opt(map) :: {:ok, binary} | {:error, atom, binary}
  @signed_at_error {:error, :invalid_input, "signed_at"}
  defp signed_at_opt(%{signed_at: %DateTime{time_zone: "Etc/UTC"} = dt}) do
    {:ok, %DateTime{dt | microsecond: {0, 0}} |> Util.amz_dt_iso()}
  end
  defp signed_at_opt(%{signed_at: s}) when is_binary(s) do
    case Util.parse_amz_dt(s) do
      {:ok, _} -> {:ok, s}
      _ -> @signed_at_error
    end
  end
  defp signed_at_opt(%{signed_at: _}), do: @signed_at_error
  defp signed_at_opt(_), do: {:ok, Util.amz_dt_now() |> Util.amz_dt_iso()}

  @region_error {:error, :invalid_input, "region"}
  defp region_opt(%{region: r}) when is_binary(r), do: {:ok, r}
  defp region_opt(%{region: _}), do: @region_error
  defp region_opt(_), do: {:ok, "us-east-1"}

  @service_error {:error, :invalid_input, "service"}
  defp service_opt(%{service: s}) when is_binary(s), do: {:ok, s}
  defp service_opt(%{service: _}), do: @service_error
  defp service_opt(_), do: {:ok, "s3"}

  @access_key_error {:error, :invalid_input, "access_key"}
  @secret_error {:error, :invalid_input, "secret/signing_key"}
  @spec creds_opts(map) :: {:ok, map} | {:error, term}
  defp creds_opts(%{} = opts_map) do
    ak = opts_map[:access_key]
    sk = opts_map[:signing_key]
    se = opts_map[:secret] || System.get_env("AWS_SECRET_ACCESS_KEY")

    cond do
      is_binary(ak) && is_binary(sk) -> {:ok, %{access_key: ak, signing_key: sk}}
      is_binary(ak) && is_binary(se) -> {:ok, %{access_key: ak, secret: se}}
      !is_binary(ak) -> @access_key_error
      true -> @secret_error
    end
  end

  @provider_error {:error, :invalid_input, "provider"}
  defp provider_opt(%{provider: p}) when p != nil and is_atom(p), do: {:ok, p}
  defp provider_opt(_), do: @provider_error

  @spec list_to_map([{binary, binary}]) :: map
  defp list_to_map(list) do
    collect_values = fn {k, v}, acc ->
      if Map.has_key?(acc, k) do
        Map.put(acc, k, List.wrap(Map.get(acc, k)) ++ List.wrap(v))
      else
        Map.put(acc, k, v)
      end
    end

    list |> Enum.reduce(%{}, collect_values)
  end
end
