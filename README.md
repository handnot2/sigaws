# Sigaws

An Elixir library to sign and verify HTTP requests using AWS Signature V4.

[![Inline docs](http://inch-ci.org/github/handnot2/sigaws.svg)](http://inch-ci.org/github/handnot2/sigaws)

## Installation

This package can be installed by adding `sigaws` to your list of dependencies
in `mix.exs`:

```elixir
def deps do
  [{:sigaws, "~> 0.1.0"}]
end
```

## Documentation

+ [Blog](https://handnot2.github.io/blog/elixir/aws-signature-sigaws)
+ [Module Doc](https://hexdocs.pm/sigaws)
+ [Plug built using this](https://hexdocs.pm/plug_sigaws)

## Examples

### Signature to be passed as request headers

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

### Signature to be passed in query string ("presigned" URL)

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

### Signature Verification

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

The above example is using the `sigaws_quickstart_provider` Hex package.
Check the blog listed earlier.

## Test Suite

Part of the tests in this package rely on AWS Signature Version 4 Test Suite.
This test suite should be downloaded and unpacked before running the tests.

```sh
mkdir -p test/testsuite
cd test/testsuite
wget https://docs.aws.amazon.com/general/latest/gr/samples/aws-sig-v4-test-suite.zip
unzip aws-sig-v4-test-suite.zip
```
