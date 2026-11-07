/**
 * Optional OpenID Connect sign-in for self-hosted instances.
 *
 * Off unless PAPERCLIP_AUTH_OIDC_ISSUER, PAPERCLIP_AUTH_OIDC_CLIENT_ID and
 * PAPERCLIP_AUTH_OIDC_CLIENT_SECRET are all set. When off, nothing here is
 * registered: no provider, no endpoint, no user-validation hook, and Better
 * Auth's options are byte-identical to an instance without this file.
 *
 * Security contract (each item is covered by oidc tests):
 * - The IdP must assert `email_verified === true` (boolean). Anything else is
 *   refused before a user is created, linked, or signed in.
 * - An existing local user is linked only on a case-insensitive email match
 *   plus that verified claim, and only when sign-up is disabled (local
 *   accounts are then operator-provisioned, so nobody can pre-register a
 *   victim's address and wait for the victim's SSO login to link to it).
 * - No user is created when PAPERCLIP_AUTH_DISABLE_SIGN_UP is true.
 * - When PAPERCLIP_AUTH_OIDC_ALLOWED_GROUPS is set, the `groups` claim must
 *   contain one of them on every sign-in, not just the first.
 * - State, PKCE, nonce and id_token signature checks are Better Auth's; the
 *   id_token must verify against the issuer's discovery JWKS.
 * - Return URLs for the OIDC flow must be same-origin relative paths.
 * - The client secret only ever leaves this process towards the IdP's token
 *   endpoint. It is never logged and never part of a response.
 * - A failed or hung discovery disables OIDC only; email/password sign-in
 *   (the break-glass path) keeps working.
 */

import { createAuthEndpoint, createAuthMiddleware, APIError } from "better-auth/api";
import { genericOAuth } from "better-auth/plugins";
import type { BetterAuthPlugin } from "better-auth";
import { logger } from "../middleware/logger.js";

export const OIDC_PROVIDER_ID = "oidc";
export const OIDC_CONFIG_PATH = "/oidc/config";
const DEFAULT_SCOPES = ["openid", "email", "profile"];
const DISCOVERY_TIMEOUT_MS = 10_000;

export type OidcAuthConfig = {
  issuer: string;
  discoveryUrl: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
  providerName: string;
  allowedGroups: string[];
  autoRedirect: boolean;
};

/** What the sign-in page may know. Never the secret, issuer or client id. */
export type OidcPublicConfig = {
  providerId: typeof OIDC_PROVIDER_ID;
  displayName: string;
  autoRedirect: boolean;
};

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]" || hostname === "::1";
}

function splitList(value: string | undefined, separator: RegExp): string[] {
  return (value ?? "")
    .split(separator)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeGroup(group: string): string {
  return group.trim().replace(/^\//, "");
}

/**
 * Reads OIDC settings from the environment. Returns null when OIDC is off.
 * A partial or malformed configuration throws: running with SSO half-on is a
 * misconfiguration, and unsetting the variables is the documented rollback.
 */
export function loadOidcAuthConfig(env: NodeJS.ProcessEnv = process.env): OidcAuthConfig | null {
  const issuerRaw = env.PAPERCLIP_AUTH_OIDC_ISSUER?.trim();
  const clientId = env.PAPERCLIP_AUTH_OIDC_CLIENT_ID?.trim();
  const clientSecret = env.PAPERCLIP_AUTH_OIDC_CLIENT_SECRET?.trim();
  const setCount = [issuerRaw, clientId, clientSecret].filter(Boolean).length;
  if (setCount === 0) return null;
  if (setCount < 3) {
    throw new Error(
      "PAPERCLIP_AUTH_OIDC_ISSUER, PAPERCLIP_AUTH_OIDC_CLIENT_ID and PAPERCLIP_AUTH_OIDC_CLIENT_SECRET must be set together to enable OIDC sign-in",
    );
  }

  let issuerUrl: URL;
  try {
    issuerUrl = new URL(issuerRaw!);
  } catch {
    throw new Error("PAPERCLIP_AUTH_OIDC_ISSUER must be an absolute URL");
  }
  if (issuerUrl.protocol !== "https:" && !(issuerUrl.protocol === "http:" && isLoopbackHost(issuerUrl.hostname))) {
    throw new Error("PAPERCLIP_AUTH_OIDC_ISSUER must use https (http is allowed only for loopback hosts)");
  }
  if (issuerUrl.search || issuerUrl.hash || issuerUrl.username || issuerUrl.password) {
    throw new Error("PAPERCLIP_AUTH_OIDC_ISSUER must not contain credentials, a query or a fragment");
  }
  const issuer = issuerUrl.toString().replace(/\/+$/, "");

  const scopes = splitList(env.PAPERCLIP_AUTH_OIDC_SCOPES, /[\s,]+/);
  return {
    issuer,
    discoveryUrl: `${issuer}/.well-known/openid-configuration`,
    clientId: clientId!,
    clientSecret: clientSecret!,
    scopes: scopes.length > 0 ? scopes : DEFAULT_SCOPES,
    providerName: env.PAPERCLIP_AUTH_OIDC_PROVIDER_NAME?.trim() || "SSO",
    allowedGroups: splitList(env.PAPERCLIP_AUTH_OIDC_ALLOWED_GROUPS, /,/).map(normalizeGroup).filter(Boolean),
    autoRedirect: env.PAPERCLIP_AUTH_OIDC_AUTO_REDIRECT?.trim().toLowerCase() === "true",
  };
}

export function oidcPublicConfig(config: OidcAuthConfig): OidcPublicConfig {
  return {
    providerId: OIDC_PROVIDER_ID,
    displayName: config.providerName,
    autoRedirect: config.autoRedirect,
  };
}

type OidcRejection = { error: string; errorDescription: string };

/** Policy for one OIDC identity, given the raw (unmapped) id_token/userinfo claims. */
export function evaluateOidcProfile(
  profile: Record<string, unknown> | undefined,
  config: Pick<OidcAuthConfig, "allowedGroups">,
): OidcRejection | null {
  if (!profile || profile.email_verified !== true) {
    return { error: "oidc_email_not_verified", errorDescription: "The identity provider did not confirm this email address." };
  }
  if (config.allowedGroups.length > 0) {
    const raw = profile.groups;
    const groups = (Array.isArray(raw) ? raw : typeof raw === "string" ? [raw] : [])
      .filter((group): group is string => typeof group === "string")
      .map(normalizeGroup);
    if (!groups.some((group) => config.allowedGroups.includes(group))) {
      return { error: "oidc_group_not_allowed", errorDescription: "Your account is not in a group allowed to use this instance." };
    }
  }
  return null;
}

/** Only same-origin relative paths: "/x", never "//host", "/\\host" or absolute URLs. */
export function isSafeRelativeReturnPath(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  if (typeof value !== "string") return false;
  if (!value.startsWith("/") || value.startsWith("//")) return false;
  return !/[\\\x00-\x20\x7f]/.test(value);
}

type ValidateUserInfoInput = {
  user: Record<string, unknown>;
  source: {
    action: "create-user" | "link-account" | "sign-in";
    method: string;
    oauth?: { providerId: string; profile?: Record<string, unknown> };
  };
};

/**
 * Better Auth calls this before it creates, links or signs in any user, for
 * every method. Only the OIDC provider is judged here; everything else passes.
 */
export function createOidcUserValidator(config: OidcAuthConfig, opts: { disableSignUp: boolean }) {
  return ({ source }: ValidateUserInfoInput): OidcRejection | undefined => {
    if (source.method !== "oauth" || source.oauth?.providerId !== OIDC_PROVIDER_ID) return undefined;
    if (source.action === "create-user" && opts.disableSignUp) {
      return { error: "signup_disabled", errorDescription: "No Paperclip account exists for this email address." };
    }
    return evaluateOidcProfile(source.oauth.profile, config) ?? undefined;
  };
}

function withDiscoveryGuard(plugin: BetterAuthPlugin, config: OidcAuthConfig): BetterAuthPlugin {
  const init = plugin.init;
  if (!init) return plugin;
  type Init = NonNullable<BetterAuthPlugin["init"]>;
  type InitResult = Awaited<ReturnType<Init>>;
  const guarded = async (ctx: Parameters<Init>[0]): Promise<InitResult | undefined> => {
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        Promise.resolve(init(ctx)),
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error(`discovery timed out after ${DISCOVERY_TIMEOUT_MS}ms`)), DISCOVERY_TIMEOUT_MS);
          timer.unref?.();
        }),
      ]);
    } catch (error) {
      // Only the issuer is logged; the message comes from Better Auth's own
      // provider setup and never includes the client secret.
      logger.error(
        { issuer: config.issuer, err: error instanceof Error ? error.message : String(error) },
        "OIDC sign-in disabled: provider discovery failed. Email/password sign-in is unaffected; restart after fixing the issuer.",
      );
      return undefined;
    } finally {
      if (timer) clearTimeout(timer);
    }
  };
  // Same contract as the wrapped init: resolve to its result, or to nothing.
  return { ...plugin, init: guarded as Init };
}

/** Public config endpoint, plus the return-URL and id_token guard for OIDC sign-in and linking. */
function oidcSupportPlugin(config: OidcAuthConfig): BetterAuthPlugin {
  const publicConfig = oidcPublicConfig(config);
  return {
    id: "paperclip-oidc",
    endpoints: {
      paperclipOidcConfig: createAuthEndpoint(OIDC_CONFIG_PATH, { method: "GET" }, async (ctx) => ctx.json(publicConfig)),
    },
    hooks: {
      before: [
        {
          // /link-social takes the same callbackURL/errorCallbackURL/idToken body.
          matcher: (ctx) => ctx.path === "/sign-in/social" || ctx.path === "/link-social",
          handler: createAuthMiddleware(async (ctx) => {
            const body = (ctx.body ?? {}) as Record<string, unknown>;
            if (body.provider !== OIDC_PROVIDER_ID) return;
            for (const key of ["callbackURL", "errorCallbackURL", "newUserCallbackURL"] as const) {
              if (!isSafeRelativeReturnPath(body[key])) {
                throw new APIError("FORBIDDEN", { code: "INVALID_CALLBACK_URL", message: `Invalid ${key}` });
              }
            }
            // Better Auth accepts a raw id_token here whenever the provider has an
            // id_token config. That path skips state, PKCE and (unless the caller
            // sends one) the nonce, so a leaked id_token could be replayed. Only
            // the redirect flow is allowed.
            if (body.idToken !== undefined) {
              throw new APIError("FORBIDDEN", { code: "ID_TOKEN_SIGN_IN_DISABLED", message: "Use the redirect sign-in flow" });
            }
          }),
        },
      ],
    },
  };
}

/**
 * The Better Auth options OIDC adds. Merge into the instance options only when
 * `loadOidcAuthConfig` returned a config.
 */
export function buildOidcAuthOptions(config: OidcAuthConfig, opts: { disableSignUp: boolean }) {
  const provider = genericOAuth({
    config: [
      {
        providerId: OIDC_PROVIDER_ID,
        name: config.providerName,
        discoveryUrl: config.discoveryUrl,
        clientId: config.clientId,
        clientSecret: config.clientSecret,
        scopes: config.scopes,
        pkce: true,
        requireIdTokenVerification: true,
        disableSignUp: opts.disableSignUp,
        // Strict boolean: a string "true" or a missing claim is not verified.
        mapProfileToUser: (profile: Record<string, unknown>) => {
          const email = typeof profile.email === "string" ? profile.email : undefined;
          const name = typeof profile.name === "string" && profile.name.trim()
            ? profile.name.trim()
            : typeof profile.preferred_username === "string" && profile.preferred_username.trim()
              ? profile.preferred_username.trim()
              : email?.split("@")[0];
          return { emailVerified: profile.email_verified === true, ...(name ? { name } : {}) };
        },
      },
    ],
  }) as BetterAuthPlugin;

  if (!opts.disableSignUp) {
    logger.warn(
      { issuer: config.issuer },
      "OIDC sign-in is on while sign-up is open: OIDC will not link to existing password accounts. Set PAPERCLIP_AUTH_DISABLE_SIGN_UP=true to sign existing users in through OIDC.",
    );
  }

  return {
    plugins: [withDiscoveryGuard(provider, config), oidcSupportPlugin(config)],
    validateUserInfo: createOidcUserValidator(config, opts),
    accountLinking: {
      // Paperclip never verifies local email addresses, so Better Auth's
      // default (link only to a locally verified row) would make linking
      // impossible. It is safe to relax only when sign-up is disabled: then
      // every local row was provisioned by an operator or an invite, and the
      // IdP's verified email is the proof of ownership.
      requireLocalEmailVerified: !opts.disableSignUp,
    },
  };
}
