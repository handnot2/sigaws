defmodule VerificationProvider do
  @behaviour Sigaws.Provider

  defp test_regions, do: ["us-east-1", "alpha-quad", "gamma-quad"]
  defp test_services, do: ["s3", "d3", "my-service"]
  defp test_creds, do: %{"ak1" => "sk1", "ak2" => "sk2", "ak3" => "sk3"}

  def pre_verification(%Sigaws.Ctxt{} = ctxt) do
    cond do
      !(ctxt.region in test_regions()) ->
        {:error, :invalid_data, "region"}

      !(ctxt.service in test_services()) ->
        {:error, :invalid_data, "service"}

      true ->
        case Sigaws.Util.check_expiration(ctxt) do
          :ok -> :ok
          error -> error
        end
    end
  end

  def signing_key(%Sigaws.Ctxt{} = ctxt) do
    creds = test_creds()

    if Map.has_key?(creds, ctxt.access_key) do
      secret = Map.get(creds, ctxt.access_key)
      {:ok, dt} = Sigaws.Util.parse_amz_dt(ctxt.signed_at_amz_dt)

      dt
      |> DateTime.to_date()
      |> Sigaws.Util.signing_key(ctxt.region, ctxt.service, secret)
    else
      {:error, :invalid_data, "access_key"}
    end
  end
end

defmodule SigawsTest do
  use ExUnit.Case
  doctest Sigaws
  doctest Sigaws.Util

  def assert_all_sig_headers(sig_headers) do
    assert Map.has_key?(sig_headers, "Authorization")
    assert Map.has_key?(sig_headers, "X-Amz-Algorithm")
    assert Map.has_key?(sig_headers, "X-Amz-Content-Sha256")
    assert Map.has_key?(sig_headers, "X-Amz-Date")
    assert Map.has_key?(sig_headers, "X-Amz-SignedHeaders")
  end

  def assert_all_sig_params(sig_params) do
    assert Map.has_key?(sig_params, "X-Amz-Algorithm")
    assert Map.has_key?(sig_params, "X-Amz-Credential")
    assert Map.has_key?(sig_params, "X-Amz-Date")
    assert Map.has_key?(sig_params, "X-Amz-SignedHeaders")
    assert Map.has_key?(sig_params, "X-Amz-Signature")
  end

  test "sign_req" do
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    assert {:ok, sig_data, _} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)
  end

  test "sign_url" do
    opts = [region: "gamma-quad", service: "d3", access_key: "ak2", secret: "sk2"]
    assert {:ok, sig_data, _} = Sigaws.sign_url("http://localhost/", opts)
    assert_all_sig_params(sig_data)
  end

  test "sign_req: not path component" do
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    assert {:ok, sig_data, _} = Sigaws.sign_req("http://localhost", opts)
    assert_all_sig_headers(sig_data)
  end

  test "sign_url: not path component" do
    opts = [region: "gamma-quad", service: "d3", access_key: "ak2", secret: "sk2"]
    assert {:ok, sig_data, _} = Sigaws.sign_url("http://localhost", opts)
    assert_all_sig_params(sig_data)
  end

  test "sign_req: valid signed_at UTC" do
    now = DateTime.utc_now() |> Map.put(:microsecond, {0, 0})
    opts = [region: "gamma-quad", service: "d3", access_key: "ak2", secret: "sk2"]
    opts = opts |> Keyword.put(:signed_at, now)
    assert {:ok, sig_data, _} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    {:ok, dt} = Sigaws.Util.parse_amz_dt(Map.get(sig_data, "X-Amz-Date"))
    assert now == dt
  end

  test "sign_url: valid signed_at UTC" do
    now = DateTime.utc_now() |> Map.put(:microsecond, {0, 0})
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = opts |> Keyword.put(:signed_at, now)
    assert {:ok, sig_data, _} = Sigaws.sign_url("http://localhost/", opts)
    assert_all_sig_params(sig_data)

    {:ok, dt} = Sigaws.Util.parse_amz_dt(Map.get(sig_data, "X-Amz-Date"))
    assert now == dt
  end

  test "sign_req: valid signed_at AMZ-ISO" do
    now = Sigaws.Util.amz_dt_now() |> Sigaws.Util.amz_dt_iso()
    opts = [region: "gamma-quad", service: "d3", access_key: "ak2", secret: "sk2"]
    opts = opts |> Keyword.put(:signed_at, now)
    assert {:ok, sig_data, _} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert now == Map.get(sig_data, "X-Amz-Date")
  end

  test "sign_url: valid signed_at AMZ-ISO" do
    now = Sigaws.Util.amz_dt_now() |> Sigaws.Util.amz_dt_iso()
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = opts |> Keyword.put(:signed_at, now)
    assert {:ok, sig_data, _} = Sigaws.sign_url("http://localhost/", opts)
    assert_all_sig_params(sig_data)

    assert now == Map.get(sig_data, "X-Amz-Date")
  end

  test "sign_req: invalid signed_at AMZ-ISO" do
    now =
      Sigaws.Util.amz_dt_now()
      |> Sigaws.Util.amz_dt_iso()
      |> String.replace("Z", "X")

    opts = [region: "gamma-quad", service: "d3", access_key: "ak2", secret: "sk2"]
    opts = opts |> Keyword.put(:signed_at, now)
    assert {:error, _, _} = Sigaws.sign_req("http://localhost/", opts)
  end

  test "sign_url: invalid signed_at AMZ-ISO" do
    now =
      Sigaws.Util.amz_dt_now()
      |> Sigaws.Util.amz_dt_iso()
      |> String.replace("Z", "X")

    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = opts |> Keyword.put(:signed_at, now)
    assert {:error, _, _} = Sigaws.sign_url("http://localhost/", opts)
  end

  test "sign_req: expiration" do
    headers = %{"X-Amz-Expires" => "2"}
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = Keyword.merge(opts, headers: headers, signed_at: DateTime.utc_now())
    assert {:ok, sig_data, _} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    :timer.sleep(3000)

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.merge(headers, sig_data),
               provider: VerificationProvider
             )
  end

  test "sign_url: expiration" do
    params = %{"X-Amz-Expires" => "2"}
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = Keyword.merge(opts, params: params, signed_at: DateTime.utc_now())
    assert {:ok, sig_data, _} = Sigaws.sign_url("http://localhost/", opts)
    assert_all_sig_params(sig_data)

    :timer.sleep(3000)

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.merge(params, sig_data),
               provider: VerificationProvider
             )
  end

  test "sign_req: expiration tampering" do
    headers = %{"X-Amz-Expires" => "2"}
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = Keyword.merge(opts, headers: headers, signed_at: DateTime.utc_now())
    assert {:ok, sig_data, _} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    :timer.sleep(3000)

    headers = %{"X-Amz-Expires" => "invalid-value"}

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.merge(headers, sig_data),
               provider: VerificationProvider
             )

    headers = %{"X-Amz-Expires" => "0"}

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.merge(headers, sig_data),
               provider: VerificationProvider
             )

    headers = %{"X-Amz-Expires" => "-10"}

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.merge(headers, sig_data),
               provider: VerificationProvider
             )

    headers = %{"X-Amz-Expires" => "5"}

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.merge(headers, sig_data),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: sig_data,
               provider: VerificationProvider
             )
  end

  test "sign_url: expiration tampering" do
    params = %{"X-Amz-Expires" => "2"}
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = Keyword.merge(opts, params: params, signed_at: DateTime.utc_now())
    assert {:ok, sig_data, _} = Sigaws.sign_url("http://localhost/", opts)
    assert_all_sig_params(sig_data)

    :timer.sleep(3000)

    params = %{"X-Amz-Expires" => "invalid-value"}

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.merge(params, sig_data),
               provider: VerificationProvider
             )

    params = %{"X-Amz-Expires" => "0"}

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.merge(params, sig_data),
               provider: VerificationProvider
             )

    params = %{"X-Amz-Expires" => "-10"}

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.merge(params, sig_data),
               provider: VerificationProvider
             )

    params = %{"X-Amz-Expires" => "5"}

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.merge(params, sig_data),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: sig_data,
               provider: VerificationProvider
             )
  end

  test "sign_req: X-Amz-Date tampering" do
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = Keyword.merge(opts, signed_at: DateTime.utc_now())
    assert {:ok, sig_data, _} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.put(sig_data, "X-Amz-Date", "20150310T000000Z"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.put(sig_data, "X-Amz-Date", "20150310T990000Z"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.put(sig_data, "X-Amz-Date", "20150310"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.put(sig_data, "X-Amz-Date", "invalid-date"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.put(sig_data, "X-Amz-Date", ""),
               provider: VerificationProvider
             )
  end

  test "sign_url: X-Amz-Date tampering" do
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = Keyword.merge(opts, signed_at: DateTime.utc_now())
    assert {:ok, sig_data, _} = Sigaws.sign_url("http://localhost/", opts)
    assert_all_sig_params(sig_data)

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.put(sig_data, "X-Amz-Date", "20150310T000000Z"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.put(sig_data, "X-Amz-Date", "20150310T990000Z"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.put(sig_data, "X-Amz-Date", "20150310"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.put(sig_data, "X-Amz-Date", "invalid-date"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.put(sig_data, "X-Amz-Date", ""),
               provider: VerificationProvider
             )
  end

  test "sign_req: missing signature elements" do
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = Keyword.merge(opts, signed_at: DateTime.utc_now())
    assert {:ok, sig_data, _} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.delete(sig_data, "Authorization"),
               provider: VerificationProvider
             )

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.delete(sig_data, "X-Amz-Algorithm"),
               provider: VerificationProvider
             )

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.delete(sig_data, "X-Amz-Content-Sha256"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.delete(sig_data, "X-Amz-Date"),
               provider: VerificationProvider
             )

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               headers: Map.delete(sig_data, "X-Amz-SignedHeaders"),
               provider: VerificationProvider
             )
  end

  test "sign_url: missing signature elements" do
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = Keyword.merge(opts, signed_at: DateTime.utc_now())
    assert {:ok, sig_data, _} = Sigaws.sign_url("http://localhost/", opts)
    assert_all_sig_params(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.delete(sig_data, "X-Amz-Algorithm"),
               provider: VerificationProvider
             )

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.delete(sig_data, "X-Amz-Content-Sha256"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.delete(sig_data, "X-Amz-Credential"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.delete(sig_data, "X-Amz-Date"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.delete(sig_data, "X-Amz-Signature"),
               provider: VerificationProvider
             )

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               params: Map.delete(sig_data, "X-Amz-SignedHeaders"),
               provider: VerificationProvider
             )
  end

  test "sign_req: malformed authorization header" do
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = Keyword.merge(opts, signed_at: DateTime.utc_now())
    assert {:ok, sig_data, _} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    incorrect_az = [
      "",
      "AWS4-HMAC-SHA256 Credential=id_dt_rg_sv_aws4_request, SignedHeaders=a, Signature=b",
      "AWS4-HMAC-SHA256 Credential=id/dt/rg/sv/aws4_request, SignedHeaders=a, Signature=b",
      "AWS4-HMAC-SHA256 Credential=id/dt/xx/rg/sv/aws4_request, SignedHeaders=a, Signature=b",
      "AWS4-HMAC-SHA256 Credential=id/dt/sv/aws4_request, SignedHeaders=a, Signature=b",
      "AWS4-HMAC-SHA256 Credential=id/20170327/rg/sv/aws4_request, SignedHeaders=a, Signature=b",
      "AWS4-HMAC-SHA256 Credential=id/20170327/gamma-quad/sv/aws4_request, SignedHeaders=a, Signature=b",
      "AWS4-HMAC-SHA256 Credential=id/20170327/gamma-quad/d3/aws4_request, SignedHeaders=a, Signature=b",
      "AWS4-HMAC-SHA256 Credential=ak3/20170327/gamma-quad/d3/aws4_request, SignedHeaders=a, Signature=b",
      "AWS4-HMAC-SHA256 Credential=ak3/20170327/gamma-quad/d3/aws4_request, SignedHeaders=, Signature=b",
      "AWS4-HMAC-SHA256 Credential=ak3/20170327/gamma-quad/d3/aws4_request, SignedHeaders=host, Signature=b",
      "AWS4-HMAC-SHA256 Credential=ak3/20170327/gamma-quad/d3/aws4_request, SignedHeaders=host, Signature=b",
      "AWS4-HMAC-SHA256 Credential=ak3/20173327/gamma-quad/d3/aws4_request, SignedHeaders=host, Signature=b",
      "AWS4-HMAC-SHA256 Credential=/20170327/gamma-quad/d3/aws4_request, SignedHeaders=host, Signature=b"
    ]

    for az <- incorrect_az do
      assert {:error, _, _} =
               Sigaws.verify(
                 "http://localhost/",
                 headers: Map.put(sig_data, "Authorization", az),
                 provider: VerificationProvider
               )
    end
  end

  test "sign_url: malformed X-Amz-Credential parameter" do
    opts = [region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    opts = Keyword.merge(opts, signed_at: DateTime.utc_now())
    assert {:ok, sig_data, _} = Sigaws.sign_url("http://localhost/", opts)
    assert_all_sig_params(sig_data)

    incorrect_cr = [
      "",
      "id_dt_rg_sv_aws4_request",
      "id/dt/rg/sv/aws4_request",
      "id/dt/xx/rg/sv/aws4_request",
      "id/dt/sv/aws4_request",
      "id/20170327/rg/sv/aws4_request",
      "id/20170327/gamma-quad/sv/aws4_request",
      "id/20170327/gamma-quad/d3/aws4_request",
      "ak3/20170327/gamma-quad/d3/aws4_request",
      "ak3/20170327/gamma-quad/d3/aws4_request",
      "ak3/20170327/gamma-quad/d3/aws4_request",
      "ak3/20170327/gamma-quad/d3/aws4_request",
      "ak3/20173327/gamma-quad/d3/aws4_request",
      "/20170327/gamma-quad/d3/aws4_request"
    ]

    for cr <- incorrect_cr do
      assert {:error, _, _} =
               Sigaws.verify(
                 "http://localhost/",
                 params: Map.put(sig_data, "X-Amz-Credential", cr),
                 provider: VerificationProvider
               )
    end
  end

  test "post with text body" do
    body = "body"

    opts = [
      method: "POST",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: body
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "POST",
               headers: sig_data,
               body: body,
               provider: VerificationProvider
             )
  end

  test "post without body" do
    opts = [method: "POST", region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "POST",
               headers: sig_data,
               provider: VerificationProvider
             )
  end

  test "post with unsigned body" do
    opts = [
      method: "POST",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: :unsigned
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "POST",
               headers: sig_data,
               body: "some body",
               provider: VerificationProvider
             )
  end

  test "post with text body tampering" do
    body = "body"

    opts = [
      method: "POST",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: body
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:error, :verification_failed, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "POST",
               headers: sig_data,
               body: "some other body",
               provider: VerificationProvider
             )
  end

  test "post without body with tampering" do
    opts = [method: "POST", region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:error, :verification_failed, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "POST",
               headers: sig_data,
               body: "some body",
               provider: VerificationProvider
             )
  end

  test "post without body and X-Amz-Content-Sha256 header dropped from sig" do
    opts = [method: "POST", region: "us-east-1", service: "d3", access_key: "ak1", secret: "sk1"]
    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "POST",
               headers: Map.drop(sig_data, ["X-Amz-Content-Sha256"]),
               provider: VerificationProvider
             )
  end

  test "post wit text body and X-Amz-Content-Sha256 header dropped from sig" do
    body = "body"

    opts = [
      method: "POST",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: body
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "POST",
               headers: Map.drop(sig_data, ["X-Amz-Content-Sha256"]),
               body: body,
               provider: VerificationProvider
             )
  end

  test "post with unsigned body and X-Amz-Content-Sha256 header dropped from sig" do
    body = "body"

    opts = [
      method: "POST",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: :unsigned
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:error, :verification_failed, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "POST",
               headers: Map.drop(sig_data, ["X-Amz-Content-Sha256"]),
               body: body,
               provider: VerificationProvider
             )
  end

  test "get with unsigned body" do
    opts = [
      method: "GET",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: :unsigned
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "GET",
               headers: sig_data,
               provider: VerificationProvider
             )
  end

  test "get with unsigned body and X-Amz-Content-Sha256 header dropped from sig" do
    opts = [
      method: "GET",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: :unsigned
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:error, :verification_failed, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "GET",
               headers: Map.drop(sig_data, ["X-Amz-Content-Sha256"]),
               provider: VerificationProvider
             )
  end

  test "PUT with signed body verified using content hash" do
    body = "signed content"

    opts = [
      method: "PUT",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: body
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "PUT",
               body: {:content_hash, Map.get(sig_data, "X-Amz-Content-Sha256")},
               headers: sig_data,
               provider: VerificationProvider
             )
  end

  test "PUT using content hash for signing" do
    body = "signed content"
    hash = Sigaws.Util.hexdigest(body)

    opts = [
      method: "PUT",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: {:content_hash, hash}
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "PUT",
               body: body,
               headers: sig_data,
               provider: VerificationProvider
             )
  end

  test "PUT using content hash for signing - tampering" do
    body = "signed content"
    hash = Sigaws.Util.hexdigest(body)

    opts = [
      method: "PUT",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: {:content_hash, hash}
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:error, _, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "PUT",
               body: body <> "tampered",
               headers: sig_data,
               provider: VerificationProvider
             )
  end

  test "PUT using content hash for signing - file" do
    file = "test/sigaws_test.exs"
    hash = File.stream!(file) |> Sigaws.Util.hexdigest()

    opts = [
      method: "PUT",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: {:content_hash, hash}
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "PUT",
               body: File.read!(file),
               headers: sig_data,
               provider: VerificationProvider
             )
  end

  test "PUT using content hash for signing and verification - file" do
    file = "test/sigaws_test.exs"
    hash = File.stream!(file) |> Sigaws.Util.hexdigest()

    opts = [
      method: "PUT",
      region: "us-east-1",
      service: "d3",
      access_key: "ak1",
      secret: "sk1",
      body: {:content_hash, hash}
    ]

    assert {:ok, sig_data, _info} = Sigaws.sign_req("http://localhost/", opts)
    assert_all_sig_headers(sig_data)

    assert {:ok, _} =
             Sigaws.verify(
               "http://localhost/",
               method: "PUT",
               body: {:content_hash, hash},
               headers: sig_data,
               provider: VerificationProvider
             )
  end
end
