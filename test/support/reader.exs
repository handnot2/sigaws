defmodule Sigaws.Reader do
  @moduledoc false

  use Fsm, initial_state: :method

  defstate method do
    defevent collect(<<"GET "::binary, rest::binary>>) do
      req = %{
        method: "GET",
        url: rest |> String.trim_trailing(" HTTP/1.1"),
        params: %{},
        headers: %{},
        body: ""
      }
      next_state(:headers, {req, "", ""})
    end

    defevent collect(<<"POST "::binary, rest::binary>>) do
      req = %{
        method: "POST",
        url: rest |> String.trim_trailing(" HTTP/1.1"),
        params: %{},
        headers: %{},
        body: ""
      }
      next_state(:headers, {req, "", ""})
    end
  end

  defstate headers do
    defevent collect(""), data: state do
      case state do
        {req, "", _} -> next_state(:body, {req, "", ""})
        {req, name, value} ->
          req = %{req | headers: add_header(req.headers, name, value)}
          next_state(:body, {req, "", ""})
      end
    end

    defevent collect(<<" ", rest::binary>>), data: state do
      case state do
        {req, "", _} -> next_state(:body, {req, "", ""}) # error?
        {req, name, value} ->
          next_state(:headers, {req, name, value <> "\n " <> rest})
      end
    end

    defevent collect(line), data: state do
      case state do
        {req, "", _} ->
          [name, value] = line |> String.split(":")
          next_state(:headers, {req, name, value})
        {req, name, value} ->
          req = %{req | headers: add_header(req.headers, name, value)}
          [name, value] = line |> String.split(":")
          next_state(:headers, {req, name, value})
      end
    end

    defevent terminate(), data: state do
      case state do
        {req, "", _} -> next_state(:done, {req, "", ""})
        {req, name, value} ->
          req = %{req | headers: add_header(req.headers, name, value)}
          next_state(:done, {req, "", ""})
      end
    end
  end

  defstate body do
    defevent collect(line), data: state do
      {req, "", data} = state
      next_state(:body, {req, "", data <> line})
    end

    defevent terminate(), data: state do
      {req, _, body} = state
      req = %{req | body: body}
      next_state(:done, {req, "", ""})
    end
  end

  defstate done do
  end

  def get_request(fsm) do
    {req, _, _} = Sigaws.Reader.data(fsm)
    req
  end

  defp add_header(%{} = headers, n, v)
      when is_binary(n) and (is_binary(v) or is_list(v)) do
    name = normalize_header(n)
    case Map.get(headers, name) do
      nil -> Map.put(headers, name, v)
      pv  -> Map.put(headers, name, List.wrap(pv) ++ List.wrap(v))
    end
  end

  defp normalize_header(h) when is_binary(h) do
    h |> String.split("-") |> Enum.map_join("-", &String.capitalize/1)
  end
end
