# Sigaws

An Elixir library to sign and verify HTTP requests using AWS Signature V4.

[![Inline docs](http://inch-ci.org/github/handnot2/sigaws.svg)](http://inch-ci.org/github/handnot2/sigaws)

## Installation

This package can be installed by adding `sigaws` to your list of dependencies
in `mix.exs`:

```elixir
def deps do
  [{:sigaws, "~> 0.7"}]
end
```

## Documentation

+ [Blog](https://handnot2.github.io/blog/elixir/aws-signature-sigaws)
+ [Module Doc](https://hexdocs.pm/sigaws)
+ [Plug built using this](https://hexdocs.pm/plug_sigaws)

## Examples

### Signature to be passed as request headers

```elixir
url = "https://ec2.amazonaws.com/Action=DescribeRegions&Version=2013-10-15"

{:ok, %{} = sig_data, _} =
  Sigaws.sign_req(url, region: "us-east-1", service: "ec2",
    access_key: System.get_env("AWS_ACCESS_KEY_ID"),
    secret:     System.get_env("AWS_SECRET_ACCESS_KEY"))

{:ok, resp} = HTTPoison.get(url, sig_data)
```

> You can pass in request headers to be included in the signature. Make sure to merge the
> signature with the headers before sending the request.

The same example is shown here making use of the temporary credentials obtained using
**AWS STS Secure Token Service**. Assuming the temporary credentials and the session
token are made available in environment variables:

```elixir
url = "https://ec2.amazonaws.com/Action=DescribeRegions&Version=2013-10-15"
headers = %{"X-Amz-Secure-Token" => System.get_env("AWS_SESSION_TOKEN")}

{:ok, %{} = sig_data, _} =
  Sigaws.sign_req(url, region: "us-east-1", service: "ec2", headers: headers,
    access_key: System.get_env("AWS_ACCESS_KEY_ID"),
    secret:     System.get_env("AWS_SECRET_ACCESS_KEY"))

{:ok, resp} = HTTPoison.get(url, Map.merge(headers, sig_data))
```

> Make sure to merge `sig_data` with other headers before calling HTTPoison.
> If not done, the HTTP request will fail with signature verification error.

### Signature to be passed in query string ("presigned" URL)

```elixir
url = "https://iam.amazonaws.com/Action=CreateUser&UserName=NewUser&Version=2010-05-08"

{:ok, %{} = sig_data, _} =
  Sigaws.sign_req(url, region: "us-east-1", service: "iam", body: :unsigned,
    access_key: System.get_env("AWS_ACCESS_KEY_ID"),
    secret: System.get_env("AWS_SECRET_ACCESS_KEY"))

presigned_url = Sigaws.Util.add_params_to_url(url, sig_data)

{:ok, resp} = HTTPoison.get(presigned_url)
```

> When creating pre-signed URL for AWS S3, make sure to pass in `body: :unsigned`
> option. It is also very importnt to merge the signature data with other query
> parameters before sending the request (`Sigaws.Util.add_params_to_url`).
> The request will fail if these are not taken care of.

### Signature Verification

The verification process relies on a provider module that implements
`Sigaws.Provider` behavior. The provider is expected to supply the signing
key based on the information present in the context (primarily the access key).

```elixir
{:ok, %Sigaws.Ctxt{} = ctxt} =
  Sigaws.Verify(conn.request_path,
    method: conn.method,
    params: conn.query_params,
    headers: conn.req_headers,
    body: get_raw_body(conn),
    provider: SigawsQuickStartProvider)
```

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
