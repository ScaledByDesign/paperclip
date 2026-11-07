/** Query flag that keeps the password form on screen and skips the automatic IdP redirect. */
export const LOCAL_SIGN_IN_PARAM = "local";

/** Navigates the whole tab to the identity provider. Separate so tests can observe it. */
export function redirectToIdentityProvider(url: string): void {
  window.location.assign(url);
}

/**
 * Where a failed OIDC sign-in lands. The `local` flag stops the automatic
 * redirect from looping, and Better Auth appends `error=<code>` to it.
 */
export function oidcErrorReturnPath(nextPath: string): string {
  const params = new URLSearchParams({ [LOCAL_SIGN_IN_PARAM]: "1" });
  if (nextPath && nextPath !== "/") params.set("next", nextPath);
  return `/auth?${params.toString()}`;
}

const OIDC_ERROR_MESSAGES: Record<string, string> = {
  oidc_email_not_verified: "Your identity provider has not verified your email address.",
  oidc_group_not_allowed: "Your account is not in a group allowed to use this instance.",
  signup_disabled: "No Paperclip account exists for this email address. Ask an administrator to invite you.",
  account_not_linked:
    "Single sign-on could not link to the existing account for this email. The identity provider must confirm the address, and this instance must have sign-up disabled.",
};

const GENERIC_OIDC_ERROR = "Single sign-on failed. Try again or sign in with your password.";

/** Fixed text only: the code comes from the URL, so it is never echoed back. */
export function describeOidcError(code: string): string {
  return Object.prototype.hasOwnProperty.call(OIDC_ERROR_MESSAGES, code) ? OIDC_ERROR_MESSAGES[code]! : GENERIC_OIDC_ERROR;
}
