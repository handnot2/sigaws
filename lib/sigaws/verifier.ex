defmodule Sigaws.Verifier do
  @moduledoc false

  alias Sigaws.Ctxt
  alias Sigaws.Util

  @sig_params [
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Signature",
    "X-Amz-SignedHeaders"
  ]

  {:ok, az_re} =
    Regex.compile(
      "AWS4-HMAC-SHA256 Credential=(?<cr>.*),\s*" <>
        "SignedHeaders=(?<sh>.*),\s*Signature=(?<sg>.*)$"
    )

  @az_re az_re
  {:ok, cr_re} = Regex.compile("(?<ak>.+)/(?<sd>.+)/(?<rg>.+)/(?<sv>.+)/aws4_request$")
  @cr_re cr_re

  @doc """
  Determines if the request is presigned based on the query parameters.

  A request is considered presigned if `X-Amz-Signature` or `X-Amz-Credential`
  query parameter is present.
  """
  @spec presigned?(map) :: boolean
  def presigned?(params) do
    Map.has_key?(params, "X-Amz-Credential") || Map.has_key?(params, "X-Amz-Signature")
  end

  @spec verify_url(binary, map) :: {:ok, Ctxt.t()} | {:error, atom, binary}
  def verify_url(req_path, %{
        method: method,
        params: params,
        headers: headers,
        body: body,
        provider: provider
      }) do
    with {:ok, %Ctxt{} = ctxt} <- ctxt_from_params(params),
         :ok <- provider.pre_verification(ctxt),
         {:ok, signing_key} <- provider.signing_key(ctxt) do
      {_, params_to_sign} = Map.split(params, @sig_params ++ ["X-Amz-Content-Sha256"])

      headers_to_sign = headers |> Map.take(ctxt.signed_headers)

      body =
        case Map.get(params, "X-Amz-Content-Sha256") do
          nil -> ""
          "UNSIGNED-PAYLOAD" -> :unsigned
          _ -> body
        end

      result =
        Sigaws.sign_url(
          req_path,
          method: method,
          params: params_to_sign,
          headers: headers_to_sign,
          body: body,
          signed_at: ctxt.signed_at_amz_dt,
          region: ctxt.region,
          service: ctxt.service,
          access_key: ctxt.access_key,
          signing_key: signing_key
        )

      signature_to_verify = ctxt.signature

      with {:ok, sig_data, _} <- result,
           {:ok, computed_ctxt} <- ctxt_from_params(sig_data) do
        # IO.inspect(ctxt, label: "verification ctxt")
        # IO.inspect(computed_ctxt, label: "computed ctxt")
        if signature_to_verify == computed_ctxt.signature do
          {:ok, computed_ctxt}
        else
          {:error, :verification_failed, "Signature verification failed"}
        end
      else
        error -> error
      end
    else
      error -> error
    end
  end

  @spec verify_req(binary, map) :: {:ok, Ctxt.t()} | {:error, atom, binary}
  def verify_req(req_path, %{
        method: method,
        params: params,
        headers: headers,
        body: body,
        provider: provider
      }) do
    with {:ok, %Ctxt{} = ctxt} <- ctxt_from_headers(headers),
         :ok <- provider.pre_verification(ctxt),
         {:ok, signing_key} <- provider.signing_key(ctxt) do
      params_to_sign = params

      headers_to_sign = headers |> Map.take(ctxt.signed_headers)

      body =
        case Map.get(headers, "x-amz-content-sha256") do
          nil -> body || ""
          "UNSIGNED-PAYLOAD" -> :unsigned
          _ -> body
        end

      result =
        Sigaws.sign_req(
          req_path,
          method: method,
          params: params_to_sign,
          headers: headers_to_sign,
          body: body,
          signed_at: ctxt.signed_at_amz_dt,
          region: ctxt.region,
          service: ctxt.service,
          access_key: ctxt.access_key,
          signing_key: signing_key
        )

      signature_to_verify = ctxt.signature

      with {:ok, sig_data, _info} <- result,
           sig_data = Util.downcase_keys(sig_data),
           {:ok, computed_ctxt} <- ctxt_from_headers(sig_data) do
        # IO.inspect(ctxt, label: "verification ctxt")
        # IO.inspect(computed_ctxt, label: "computed ctxt")
        if signature_to_verify == computed_ctxt.signature do
          {:ok, computed_ctxt}
        else
          {:error, :verification_failed, "Signature verification failed"}
        end
      else
        error -> error
      end
    else
      error -> error
    end
  end

  @missing_sig {:error, :missing_data, "X-Amz-Signature"}
  defp get_signature(nil), do: @missing_sig
  defp get_signature(s), do: {:ok, s}

  @missing_signed_at {:error, :missing_data, "X-Amz-Date"}
  defp get_signed_at(nil), do: @missing_signed_at
  defp get_signed_at(s), do: {:ok, s}

  @missing_credential {:error, :missing_data, "Credential"}
  defp get_credential(nil), do: @missing_credential
  defp get_credential(c), do: {:ok, c}

  @missing_signedheaders {:error, :missing_data, "X-Amz-SignedHeaders"}
  defp get_signedheaders(nil), do: @missing_signedheaders
  defp get_signedheaders(h), do: {:ok, h}

  @invalid_expires {:error, :invalid_data, "X-Amz-Expires"}
  defp parse_expires(nil), do: {:ok, nil}
  defp parse_expires(s) when is_binary(s), do: parse_expires(Integer.parse(s))
  defp parse_expires({ex, ""}) when ex > 0 and ex <= 86_400, do: {:ok, ex}
  defp parse_expires(_), do: @invalid_expires

  @missing_az {:error, :missing_data, "Authorization"}
  defp get_authorization(nil), do: @missing_az
  defp get_authorization(az), do: {:ok, az}

  @invalid_az {:error, :invalid_data, "Authorization"}
  defp parse_authorization(az) when is_binary(az) do
    case Regex.named_captures(@az_re, az) do
      %{"cr" => cr, "sh" => sh, "sg" => sg} -> {:ok, {cr, sh, sg}}
      _ -> @invalid_az
    end
  end

  @invalid_cr {:error, :invalid_data, "Credential"}
  defp parse_credential(cr) when is_binary(cr) do
    case Regex.named_captures(@cr_re, cr) do
      %{"ak" => ak, "sd" => sd, "rg" => rg, "sv" => sv} -> {:ok, {ak, sd, rg, sv}}
      _ -> @invalid_cr
    end
  end

  @mismatched_date {:error, :mismatched, "X-Amz-Date"}
  defp match_signing_date(date_from_scope, dt) do
    d = dt |> DateTime.to_date() |> Date.to_string() |> String.replace("-", "")
    if d == date_from_scope, do: :ok, else: @mismatched_date
  end

  @spec ctxt_from_params(map) :: {:ok, %Ctxt{}} | {:error, atom, binary}
  defp ctxt_from_params(p) do
    with {:ok, sg} <- get_signature(Map.get(p, "X-Amz-Signature")),
         {:ok, st} <- get_signed_at(Map.get(p, "X-Amz-Date")),
         {:ok, cr} <- get_credential(Map.get(p, "X-Amz-Credential")),
         {:ok, sh} <- get_signedheaders(Map.get(p, "X-Amz-SignedHeaders")),
         {:ok, ex} <- parse_expires(Map.get(p, "X-Amz-Expires")),
         {:ok, {ak, sd, rg, sv}} <- parse_credential(cr),
         {:ok, dt} <- Util.parse_amz_dt(st),
         :ok <- match_signing_date(sd, dt) do
      sh = sh |> String.split(";") |> Enum.sort()

      {:ok, %Ctxt{
        access_key: ak,
        region: rg,
        service: sv,
        signed_at_amz_dt: st,
        expires_in: ex,
        signed_headers: sh,
        signature: sg
      }}
    else
      {:error, _, _} = error -> error
    end
  end

  @spec ctxt_from_headers(map) :: {:ok, %Ctxt{}} | {:error, atom, binary}
  defp ctxt_from_headers(%{} = h) do
    with {:ok, az} <- get_authorization(Map.get(h, "authorization")),
         {:ok, st} <- get_signed_at(Map.get(h, "x-amz-date")),
         {:ok, ex} <- parse_expires(Map.get(h, "x-amz-expires")),
         {:ok, {cr, sh, sg}} <- parse_authorization(az),
         {:ok, {ak, sd, rg, sv}} <- parse_credential(cr),
         {:ok, dt} <- Util.parse_amz_dt(st),
         :ok <- match_signing_date(sd, dt) do
      sh = sh |> String.split(";") |> Enum.sort()

      {:ok, %Ctxt{
        access_key: ak,
        region: rg,
        service: sv,
        signed_at_amz_dt: st,
        expires_in: ex,
        signed_headers: sh,
        signature: sg
      }}
    else
      {:error, _, _} = error -> error
    end
  end
end
