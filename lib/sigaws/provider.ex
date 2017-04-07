defmodule Sigaws.Provider do

  @moduledoc """
  This behavior defines the callbacks expected from an implementation needed
  for signature verification.

  The `pre_verification` callback is expected to use the context data to
  verify/validate the request. All the information available for verification
  are passed in `Sigaws.Ctxt`. This callback should return `:ok` when
  verification passes or return `{:error, atom, binary}` when it fails.
  At the minimum return an error when:

  -    region is not one of supported regions
  -    service is not one of supported services
  -    request expired (based on `signed_at_amz_dt` and `expires_in`)
  
  The `signing_key` callback is called only when
  `pre_verification` succeeds without any error. This key should be generated
  as outlined
  [here](http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html).
  The returned key is used to recompute the signature to verify against.
  A helper function to generate this (`Sigaws.Util.signing_key/4`) is provided
  for convenience. This approach of relying on a callback to get signing key
  instead of requiring the secret enables better key managment if desired.
  """

  alias Sigaws.Ctxt

  @doc """
  Validate signature info in the signed request.

  Use this to validate that only supported regions/services are accepted.
  Expiration check should be performed if the corresponding attribute is set.

  Sigaws will halt the verification process when this returns an errror. That
  same error is returned to the caller.

  | Returns | When |
  |:------- |:---- |
  | `{:error, :expired, ""}` | Check `Sigaws.Util.check_expiration/1` |
  | `{:error, :unknown, "region"}` | Region not supported |
  | `{:error, :unknown, "service"}` | Service not supported |
  | `{:error, atom, binary}` | For other errors as defined by the implementation |
  | `:ok` | Verification passes |
  """
  @callback pre_verification(ctxt :: Ctxt.t) ::
      :ok | {:error, reason :: atom, info :: binary}

  @doc """
  Return the signing key to be used for verification based on access key ID
  provided in the signature verification context.

  Return an error if there is no valid secret for the information provided.
  This will in turn halt the verification process resulting in signature
  verification failure.

  | Returns | When |
  |:------- |:---- |
  | `{:error, :unknown, "access_key"}` | Access key is unknown |
  | `{:error, atom, binary}` | For other errors as defined by the implementation |
  | `{:ok, binary}` | Valid signing key is generated |
  """
  @callback signing_key(ctxt :: Ctxt.t) ::
    {:ok, key :: binary} | {:error, reason :: atom, info :: binary}
end
