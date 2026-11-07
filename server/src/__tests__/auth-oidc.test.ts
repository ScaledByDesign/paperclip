import { describe, expect, it } from "vitest";
import {
  createOidcUserValidator,
  evaluateOidcProfile,
  isSafeRelativeReturnPath,
  loadOidcAuthConfig,
  oidcPublicConfig,
} from "../auth/oidc.js";

const base = {
  PAPERCLIP_AUTH_OIDC_ISSUER: "https://sso.example.com/realms/sbd/",
  PAPERCLIP_AUTH_OIDC_CLIENT_ID: "paperclip",
  PAPERCLIP_AUTH_OIDC_CLIENT_SECRET: "s3cret-value",
};

describe("loadOidcAuthConfig", () => {
  it("is off when nothing is set", () => {
    expect(loadOidcAuthConfig({})).toBeNull();
  });

  it("refuses a partial configuration", () => {
    expect(() => loadOidcAuthConfig({ PAPERCLIP_AUTH_OIDC_ISSUER: base.PAPERCLIP_AUTH_OIDC_ISSUER })).toThrow(/must be set together/);
  });

  it("requires https except on loopback", () => {
    expect(() => loadOidcAuthConfig({ ...base, PAPERCLIP_AUTH_OIDC_ISSUER: "http://sso.example.com" })).toThrow(/https/);
    expect(loadOidcAuthConfig({ ...base, PAPERCLIP_AUTH_OIDC_ISSUER: "http://127.0.0.1:8080" })?.issuer).toBe("http://127.0.0.1:8080");
  });

  it("parses defaults and lists", () => {
    const config = loadOidcAuthConfig({ ...base, PAPERCLIP_AUTH_OIDC_ALLOWED_GROUPS: " /atlas-admin , ops ", PAPERCLIP_AUTH_OIDC_AUTO_REDIRECT: "TRUE" });
    expect(config).toMatchObject({
      issuer: "https://sso.example.com/realms/sbd",
      discoveryUrl: "https://sso.example.com/realms/sbd/.well-known/openid-configuration",
      scopes: ["openid", "email", "profile"],
      providerName: "SSO",
      allowedGroups: ["atlas-admin", "ops"],
      autoRedirect: true,
    });
  });

  it("keeps the secret, issuer and client id out of the public config", () => {
    const publicConfig = JSON.stringify(oidcPublicConfig(loadOidcAuthConfig(base)!));
    expect(publicConfig).not.toContain("s3cret-value");
    expect(publicConfig).not.toContain("sso.example.com");
    expect(publicConfig).not.toContain("paperclip\"");
  });
});

describe("evaluateOidcProfile", () => {
  const groups = { allowedGroups: ["atlas-admin"] };
  it("needs a boolean true email_verified", () => {
    expect(evaluateOidcProfile({ email_verified: true }, { allowedGroups: [] })).toBeNull();
    expect(evaluateOidcProfile({ email_verified: "true" }, { allowedGroups: [] })?.error).toBe("oidc_email_not_verified");
    expect(evaluateOidcProfile(undefined, { allowedGroups: [] })?.error).toBe("oidc_email_not_verified");
  });

  it("matches groups with or without a leading slash, exactly", () => {
    expect(evaluateOidcProfile({ email_verified: true, groups: ["/atlas-admin"] }, groups)).toBeNull();
    expect(evaluateOidcProfile({ email_verified: true, groups: "atlas-admin" }, groups)).toBeNull();
    expect(evaluateOidcProfile({ email_verified: true, groups: ["/parent/atlas-admin"] }, groups)?.error).toBe("oidc_group_not_allowed");
    expect(evaluateOidcProfile({ email_verified: true }, groups)?.error).toBe("oidc_group_not_allowed");
  });
});

describe("createOidcUserValidator", () => {
  const config = loadOidcAuthConfig(base)!;
  it("ignores every other sign-in method", () => {
    const validate = createOidcUserValidator(config, { disableSignUp: true });
    expect(validate({ user: {}, source: { action: "create-user", method: "email-password" } })).toBeUndefined();
  });

  it("refuses OIDC user creation when sign-up is disabled", () => {
    const validate = createOidcUserValidator(config, { disableSignUp: true });
    const source = { action: "create-user" as const, method: "oauth", oauth: { providerId: "oidc", profile: { email_verified: true } } };
    expect(validate({ user: {}, source })?.error).toBe("signup_disabled");
  });
});

describe("isSafeRelativeReturnPath", () => {
  it.each(["/", "/dashboard?x=1#y", undefined])("accepts %s", (value) => expect(isSafeRelativeReturnPath(value)).toBe(true));
  it.each(["https://evil.example", "//evil.example", "/\\evil.example", "dashboard", "/a b", 42])("refuses %s", (value) =>
    expect(isSafeRelativeReturnPath(value)).toBe(false));
});
