defmodule Sigaws.Mixfile do
  use Mix.Project

  @version "0.7.2"
  @description """
  An Elixir library to sign and verify HTTP requests using AWS Signature V4.
  """
  @source_url "https://github.com/handnot2/sigaws"
  @blog_url "https://handnot2.github.io/blog/elixir/aws-signature-sigaws"
  @test_suite_url "http://docs.aws.amazon.com/general/latest/gr/signature-v4-test-suite.html"

  def project do
    [
      app: :sigaws,
      version: @version,
      description: @description,
      package: package(),
      elixir: "~> 1.4",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls]
    ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    # Specify extra applications you'll use from Erlang/Elixir
    [extra_applications: [:crypto, :logger]]
  end

  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev},
      {:fsm, "~> 0.3", only: :test},
      {:excoveralls, "~> 0.6", only: :test},
      {:inch_ex, "~> 0.5", only: [:dev, :test]}
    ]
  end

  defp package do
    [
      maintainers: ["handnot2"],
      files: ["config", "lib", "LICENSE", "mix.exs", "README.md"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Blog" => @blog_url,
        "AWS Signature V4 Test Suite" => @test_suite_url
      }
    ]
  end
end
