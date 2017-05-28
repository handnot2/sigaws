defmodule AwsSigV4Test do
  use ExUnit.Case

  alias Sigaws.Reader

  @access_key "AKIDEXAMPLE"
  @secret "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
  @tsroot "test/testsuite/aws-sig-v4-test-suite"
  @signing_opts [
    region: "us-east-1",
    service: "service",
    access_key: @access_key,
    secret: @secret
  ]

  defp gen_req(file) do
    File.stream!(file, [])
    |> Stream.map(&(String.trim_trailing(&1, "\n")))
    |> Enum.reduce(Reader.new, fn line, fsm -> Reader.collect(fsm, line) end)
    |> Reader.terminate()
    |> Reader.get_request()
  end

  defp get_authz(file) do
    re = ~r/^Authorization: /
    [authz] =
      File.stream!(file)
      |> Stream.map(&(String.trim_trailing(&1, "\n")))
      |> Stream.filter(fn x -> Regex.match?(re, x) end)
      |> Stream.map(fn x -> Regex.replace(re, x, "") end)
      |> Enum.into([])
    authz
  end

  def signing_verification_data(path_elems) do
    req_path = Path.join(path_elems) <> ".req"
    sreq_path = Path.join(path_elems) <> ".sreq"
    req = gen_req(req_path)
    {:ok, sig_data, _extra} = Sigaws.sign_req(
      req.url, method: req.method,
      params: req.params, headers: req.headers,
      body: req.body,
      signed_at: Map.get(req.headers, "X-Amz-Date"),
      region: Keyword.fetch!(@signing_opts, :region),
      service: Keyword.fetch!(@signing_opts, :service),
      access_key: @access_key,
      secret: @secret)
    authz = get_authz(sreq_path)
    {authz, sig_data}
  end

  defp run_test(name) do
    {authz, sig_data} = [@tsroot, name, name] |> signing_verification_data()
    assert authz == Map.get(sig_data, "Authorization")
  end

  excluded = [
    "post-sts-token",
    "normalize-path",
    "post-vanilla-query-nonunreserved",
    "post-vanilla-query-space"
  ]

  {:ok, tests} = File.ls(@tsroot)
  for name <- tests, !(name in excluded) do
    @name name
    test @name, do: run_test(@name)
  end
end
