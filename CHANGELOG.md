# Changelog

## 0.4.0

Added support for license activation after starting a trial and update checks for
Moonbase products that are free (not licensed).

### Breaking changes

- Call `LicenseActivator::poll()` to get state updates.
  `LicenseActivator::state_recv` is no longer public. `poll()` returns the latest
  state, which the activator has already cached.
- The minimum supported Rust version is 1.89.
- `ActivationState::Activated` has been replaced by:
  - `Cached(claims)`: Grants provisional access while work continues.
  - `Trial(claims, followup_online_activation_url)`: Grants trial access and
    provides a URL for activating a purchased license.
  - `Confirmed(claims)`: Grants confirmed access with a non-trial license.
- The activator no longer stops after installing a trial. Keep calling `poll()`
  until it returns `Confirmed`.

### Added

- `LicenseActivator::spawn_with_callback()` calls a function after each state or
  error is published, so applications can wake their event loop instead of polling.
- `check_for_update()` asks Moonbase for a product's latest version. It needs no
  license, so it also works for free products. Results are cached on disk and
  Moonbase is contacted at most once per `check_interval`.
- `is_newer_version()` compares two versions by SemVer precedence.
- `ActivationState::grants_access()` tells you if a state grants access.
- `ActivationError::RemoveCachedToken` is sent if a rejected token cannot be
  deleted.
- `ActivationMethod` and `LicenseTokenClaims` can now be cloned.

### Changed

- A valid cached online token emits `Cached` before the online check finishes.
  A successful check then emits `Confirmed` or `Trial`. If Moonbase rejects the
  token, it is deleted and `NeedsActivation` is emitted.
- Failed online checks are retried while provisional access is still valid.
  `online_token_expiration_threshold` is always the maximum age, even when
  `online_token_refresh_threshold` is longer.
- Online and offline trials now provide a follow-up online activation URL.
- `poll_online_activation` is set to false after installing a trial. Set it to
  true again when the follow-up URL is opened.
- Instances sharing a token cache coordinate across threads and processes. Only
  one of them refreshes a token at a time, accepted tokens are cached before
  their state is published, and a slow refresh or a rejection no longer
  overwrites or deletes a license installed in the meantime.
- Simultaneous `check_for_update()` calls sharing a `cache_path` result in a
  single request, and the ones arriving while it is in flight return its result.
