defmodule Sigaws.Ctxt do
  @moduledoc """
  Context containing information related to Sigaws Signature verification.

  ### Fields

  | Name | Description |
  |:---- |:----------- |
  | `access_key`<br/>&nbsp; | Access Key ID used for verification. Extracted from credential scope. |
  | `region` | From credential scope |
  | `service` | From credential scope |
  | `signed_at_amz_dt` | From `X-Amz-Date` parameter or header |
  | `expires_in`<br/>&nbsp; | From `X-Amz-Expires` parameter or header (`nil` when not specified) |
  | `signed_headers`<br/>&nbsp; | From `Authorization` header or `X-Amz-SignedHeaders` parameter. This is a list of header names normalized to lowercase. |
  | `signature` | From `Authorization` header or `X-Amz-Signature` parameter |

  This is passed to the callbacks in `Sigaws.Provider` behavior. It is also
  returned when the verification succeeds. A plug performing signature verification
  can make this context available as a plug connection assign upon successful
  verification. This facilitates separate policy enforcement plugs that could
  potentially be developed making use of this verified context.
  """

  @type signed_headers :: [binary]
  @type expires_in :: integer | nil

  @type t :: %__MODULE__{
    access_key: binary,
    region: binary,
    service: binary,
    signed_at_amz_dt: binary,
    expires_in: expires_in,
    signed_headers: signed_headers,
    signature: binary
  }

  defstruct [:access_key, :region, :service,
             :signed_at_amz_dt, :expires_in,
             :signed_headers, :signature]
end
