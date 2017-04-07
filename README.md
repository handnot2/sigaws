# Sigaws

An Elixir library to sign and verify HTTP requests using AWS Signature V4.

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

## Test Suite

Part of the tests in this package rely on AWS Signature Version 4 Test Suite.
This test suite should be downloaded and unpacked before running the tests.

```sh
$ mkdir -p test/testsuite
$ cd test/testsuite
$ wget https://s3.amazonaws.com/awsdocs/aws-sig-v4-test-suite.zip
$ unzip aws-sig-v4-test-suite.zip
```
