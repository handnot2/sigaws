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
    req =
      File.stream!(file, [:read])
      |> Stream.map(&(String.trim_leading(&1, <<0xfeff::utf8>>)))
      |> Stream.map(&(String.trim_trailing(&1, "\n")))
      |> Enum.reduce(Reader.new, fn line, fsm -> Reader.collect(fsm, line) end)
      |> Reader.terminate()
      |> Reader.get_request()

    %{req | url: "http://" <> req.headers["Host"] <> req.url}
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

  def signing_verification_data(path_to_req_file) do
    rootname = Path.rootname(path_to_req_file, ".req")
    req_path = rootname <> ".req"
    sreq_path = rootname <> ".sreq"
    req = gen_req(req_path)

    {:ok, sig_data, _extra} = Sigaws.sign_req(
      req.url, method: req.method,
      params: req.params, headers: req.headers,
      body: req.body,
      signed_at: Map.get(req.headers, "X-Amz-Date"),
      region: Keyword.fetch!(@signing_opts, :region),
      service: Keyword.fetch!(@signing_opts, :service),
      access_key: @access_key,
      secret: @secret,
      normalize_path: true)
    authz = get_authz(sreq_path)
    {authz, sig_data}
  end

  defp run_test(path_to_req_file) do
    {authz, sig_data} = path_to_req_file |> signing_verification_data()
    assert authz == Map.get(sig_data, "Authorization")
  end

  excluded = [
    "post-sts-token",
    "post-vanilla-query-nonunreserved",
    "post-vanilla-query-space",
  ]

  for path_to_req_file <- Path.wildcard(@tsroot <> "/**/*.req"),
      !String.contains?(path_to_req_file, excluded) do
    @name path_to_req_file
    test @name, do: run_test(@name)
  end
end
