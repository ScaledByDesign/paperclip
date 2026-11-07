/**
 * OIDC sign-in end to end: the real Better Auth mount, the real Drizzle schema
 * on a migrated Postgres, and a minimal in-process OpenID provider that signs
 * RS256 id_tokens and enforces PKCE, nonce and the client secret the way a
 * real IdP does. Nothing in Better Auth is mocked.
 */

import { createHash, generateKeyPairSync, randomBytes, sign as signData, type KeyObject } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import express from "express";
import request from "supertest";
import { eq } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { authAccounts, authSessions, authUsers, authVerifications, createDb } from "@paperclipai/db";
import {
  getEmbeddedPostgresTestSupport,
  startEmbeddedPostgresTestDatabase,
} from "./helpers/embedded-postgres.js";
import { createBetterAuthHandler, createBetterAuthInstance } from "../auth/better-auth.js";
import { logger } from "../middleware/logger.js";
import type { Config } from "../config.js";

const ORIGIN = "http://127.0.0.1:41998";
const CLIENT_ID = "paperclip";
const CLIENT_SECRET = "oidc-client-secret-must-never-leak-3b1f";
const EXISTING_EMAIL = "henry@example.com";

const embeddedPostgresSupport = await getEmbeddedPostgresTestSupport();
const describeEmbeddedPostgres = embeddedPostgresSupport.supported ? describe : describe.skip;

type Profile = Record<string, unknown>;

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString("base64url");
}

/** A tiny OpenID provider: discovery, JWKS, and a strict token endpoint. */
class MockIdp {
  server!: Server;
  issuer = "";
  private readonly privateKey: KeyObject;
  private readonly publicJwk: Record<string, unknown>;
  private readonly codes = new Map<string, { challenge: string; nonce: string; redirectUri: string; profile: Profile }>();
  tokenRequests: Array<{ ok: boolean; reason?: string }> = [];

  constructor() {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    this.privateKey = privateKey;
    this.publicJwk = { ...publicKey.export({ format: "jwk" }), kid: "test-key", alg: "RS256", use: "sig" };
  }

  async start() {
    this.server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", this.issuer || "http://127.0.0.1");
      const send = (status: number, body: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(body));
      };
      if (url.pathname === "/.well-known/openid-configuration") {
        return send(200, {
          issuer: this.issuer,
          authorization_endpoint: `${this.issuer}/authorize`,
          token_endpoint: `${this.issuer}/token`,
          userinfo_endpoint: `${this.issuer}/userinfo`,
          jwks_uri: `${this.issuer}/jwks`,
          id_token_signing_alg_values_supported: ["RS256"],
          response_types_supported: ["code"],
          code_challenge_methods_supported: ["S256"],
        });
      }
      if (url.pathname === "/jwks") return send(200, { keys: [this.publicJwk] });
      if (url.pathname === "/token" && req.method === "POST") {
        let raw = "";
        req.on("data", (chunk) => (raw += chunk));
        req.on("end", () => {
          const form = new URLSearchParams(raw);
          const basic = req.headers.authorization?.startsWith("Basic ")
            ? Buffer.from(req.headers.authorization.slice(6), "base64").toString().split(":").map(decodeURIComponent)
            : null;
          const clientId = basic?.[0] ?? form.get("client_id");
          const clientSecret = basic?.[1] ?? form.get("client_secret");
          const reject = (reason: string) => {
            this.tokenRequests.push({ ok: false, reason });
            send(400, { error: "invalid_grant", error_description: reason });
          };
          if (clientId !== CLIENT_ID || clientSecret !== CLIENT_SECRET) return reject("client");
          const grant = this.codes.get(form.get("code") ?? "");
          if (!grant) return reject("code");
          this.codes.delete(form.get("code") ?? "");
          const verifier = form.get("code_verifier") ?? "";
          if (b64url(createHash("sha256").update(verifier).digest()) !== grant.challenge) return reject("pkce");
          if (form.get("redirect_uri") !== grant.redirectUri) return reject("redirect_uri");
          this.tokenRequests.push({ ok: true });
          send(200, {
            access_token: b64url(randomBytes(16)),
            token_type: "Bearer",
            expires_in: 300,
            id_token: this.idToken({ ...grant.profile, nonce: grant.nonce }),
          });
        });
        return;
      }
      send(404, { error: "not_found" });
    });
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    this.issuer = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`;
  }

  async stop() {
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  idToken(claims: Profile): string {
    const now = Math.floor(Date.now() / 1000);
    const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "test-key" }));
    const payload = b64url(JSON.stringify({ iss: this.issuer, aud: CLIENT_ID, iat: now, exp: now + 300, ...claims }));
    const signature = signData("sha256", Buffer.from(`${header}.${payload}`), this.privateKey);
    return `${header}.${payload}.${b64url(signature)}`;
  }

  /** The user "logs in" at the IdP for this authorize URL; returns the code. */
  authorize(authorizeUrl: string, profile: Profile): { code: string; state: string; redirectUri: string } {
    const url = new URL(authorizeUrl);
    expect(url.origin).toBe(this.issuer);
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    const code = b64url(randomBytes(16));
    this.codes.set(code, {
      challenge: url.searchParams.get("code_challenge") ?? "",
      nonce: url.searchParams.get("nonce") ?? "",
      redirectUri: url.searchParams.get("redirect_uri") ?? "",
      profile,
    });
    return { code, state: url.searchParams.get("state") ?? "", redirectUri: url.searchParams.get("redirect_uri") ?? "" };
  }
}

function testConfig(opts: { disableSignUp: boolean }): Config {
  return {
    deploymentMode: "authenticated",
    deploymentExposure: "private",
    authBaseUrlMode: "explicit",
    authPublicBaseUrl: ORIGIN,
    authDisableSignUp: opts.disableSignUp,
    allowedHostnames: ["127.0.0.1"],
    port: 41998,
  } as unknown as Config;
}

const OIDC_ENV_KEYS = [
  "PAPERCLIP_AUTH_OIDC_ISSUER",
  "PAPERCLIP_AUTH_OIDC_CLIENT_ID",
  "PAPERCLIP_AUTH_OIDC_CLIENT_SECRET",
  "PAPERCLIP_AUTH_OIDC_PROVIDER_NAME",
  "PAPERCLIP_AUTH_OIDC_ALLOWED_GROUPS",
  "PAPERCLIP_AUTH_OIDC_AUTO_REDIRECT",
  "PAPERCLIP_AUTH_OIDC_SCOPES",
] as const;

function sessionCookies(response: request.Response): string[] {
  const raw = response.headers["set-cookie"];
  const cookies = Array.isArray(raw) ? raw : raw ? [raw] : [];
  return cookies.filter((cookie) => cookie.includes("session_token") && !/session_token=;/.test(cookie));
}

describeEmbeddedPostgres("OIDC sign-in through Better Auth", () => {
  let database: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>> | null = null;
  let db!: ReturnType<typeof createDb>;
  const idp = new MockIdp();
  const savedEnv: Record<string, string | undefined> = {};

  beforeAll(async () => {
    for (const key of [...OIDC_ENV_KEYS, "BETTER_AUTH_SECRET", "PAPERCLIP_AUTH_RATE_LIMIT_ENABLED"]) savedEnv[key] = process.env[key];
    process.env.BETTER_AUTH_SECRET = "better-auth-secret-for-oidc-tests";
    process.env.PAPERCLIP_AUTH_RATE_LIMIT_ENABLED = "false";
    database = await startEmbeddedPostgresTestDatabase("paperclip-better-auth-oidc-");
    db = createDb(database.connectionString);
    await idp.start();
  }, 60_000);

  afterAll(async () => {
    await idp.stop();
    await database?.cleanup();
    for (const [key, value] of Object.entries(savedEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    for (const key of OIDC_ENV_KEYS) delete process.env[key];
    await db.delete(authSessions);
    await db.delete(authAccounts);
    await db.delete(authVerifications);
    await db.delete(authUsers);
    idp.tokenRequests = [];
  });

  function buildApp(opts: { oidc: boolean; disableSignUp?: boolean; allowedGroups?: string; issuer?: string }) {
    if (opts.oidc) {
      process.env.PAPERCLIP_AUTH_OIDC_ISSUER = opts.issuer ?? idp.issuer;
      process.env.PAPERCLIP_AUTH_OIDC_CLIENT_ID = CLIENT_ID;
      process.env.PAPERCLIP_AUTH_OIDC_CLIENT_SECRET = CLIENT_SECRET;
      process.env.PAPERCLIP_AUTH_OIDC_PROVIDER_NAME = "Keycloak";
      process.env.PAPERCLIP_AUTH_OIDC_AUTO_REDIRECT = "true";
      if (opts.allowedGroups) process.env.PAPERCLIP_AUTH_OIDC_ALLOWED_GROUPS = opts.allowedGroups;
    }
    const auth = createBetterAuthInstance(db, testConfig({ disableSignUp: opts.disableSignUp ?? true }), [ORIGIN]);
    const app = express();
    app.all("/api/auth/{*authPath}", createBetterAuthHandler(auth));
    return app;
  }

  async function seedExistingUser(emailVerified = false) {
    const now = new Date();
    await db.insert(authUsers).values({ id: "existing-user", name: "Henry", email: EXISTING_EMAIL, emailVerified, createdAt: now, updatedAt: now });
  }

  async function begin(agent: ReturnType<typeof request.agent>, body: Record<string, unknown> = {}) {
    return agent
      .post("/api/auth/sign-in/social")
      .set("origin", ORIGIN)
      .send({ provider: "oidc", callbackURL: "/dashboard", errorCallbackURL: "/auth?local=1", disableRedirect: true, ...body });
  }

  /** One full browser round trip: Paperclip -> IdP -> callback. */
  async function signInAs(app: express.Express, profile: Profile) {
    const agent = request.agent(app);
    const started = await begin(agent);
    expect(started.status).toBe(200);
    const { code, state } = idp.authorize(started.body.url, profile);
    const callback = await agent.get(`/api/auth/callback/oidc?code=${code}&state=${encodeURIComponent(state)}`).redirects(0);
    return { agent, started, callback };
  }

  const henry: Profile = { sub: "kc-henry", email: "Henry@Example.com", email_verified: true, name: "Henry", groups: ["/atlas-admin"] };

  it("registers nothing when OIDC is not configured", async () => {
    const app = buildApp({ oidc: false });
    expect((await request(app).get("/api/auth/oidc/config")).status).toBe(404);
    const started = await begin(request.agent(app));
    expect(started.status).toBeGreaterThanOrEqual(400);
    expect(started.body?.url).toBeUndefined();
  });

  it("with every OIDC variable empty (as compose passes them), email/password sign-up and sign-in work as before", async () => {
    // docker-compose passes `${VAR:-}`, so an unconfigured host sees empty strings, not unset.
    for (const key of OIDC_ENV_KEYS) process.env[key] = "";
    const app = buildApp({ oidc: false, disableSignUp: false });
    expect((await request(app).get("/api/auth/oidc/config")).status).toBe(404);
    const signUp = await request(app)
      .post("/api/auth/sign-up/email")
      .set("origin", ORIGIN)
      .send({ email: "founder@example.com", password: "correct-horse-battery-staple", name: "Founder" });
    expect(signUp.status).toBe(200);
    const signIn = await request(app)
      .post("/api/auth/sign-in/email")
      .set("origin", ORIGIN)
      .send({ email: "founder@example.com", password: "correct-horse-battery-staple" });
    expect(signIn.status).toBe(200);
    expect(sessionCookies(signIn).length).toBeGreaterThan(0);
    const accounts = await db.select().from(authAccounts);
    expect(accounts.map((account) => account.providerId)).toEqual(["credential"]);
  });

  it("exposes only the button label and redirect flag, and uses the callback under the public URL", async () => {
    const app = buildApp({ oidc: true });
    const config = await request(app).get("/api/auth/oidc/config");
    expect(config.status).toBe(200);
    expect(config.body).toEqual({ providerId: "oidc", displayName: "Keycloak", autoRedirect: true });

    const started = await begin(request.agent(app));
    const authorizeUrl = new URL(started.body.url);
    expect(authorizeUrl.searchParams.get("redirect_uri")).toBe(`${ORIGIN}/api/auth/callback/oidc`);
    expect(authorizeUrl.searchParams.get("client_id")).toBe(CLIENT_ID);
    expect(authorizeUrl.searchParams.get("scope")?.split(" ")).toEqual(expect.arrayContaining(["openid", "email", "profile"]));
    expect(authorizeUrl.searchParams.get("nonce")).toBeTruthy();
    expect(JSON.stringify(config.body) + started.body.url).not.toContain(CLIENT_SECRET);
  });

  it("signs a verified IdP email in as the existing user, without creating a user", async () => {
    await seedExistingUser(false);
    const app = buildApp({ oidc: true, allowedGroups: "atlas-admin" });
    const { agent, callback } = await signInAs(app, henry);

    expect(callback.status).toBe(302);
    expect(callback.headers.location).toBe("/dashboard");
    expect(sessionCookies(callback).length).toBeGreaterThan(0);
    const session = await agent.get("/api/auth/get-session");
    expect(session.body?.user?.id).toBe("existing-user");
    expect(await db.select().from(authUsers)).toHaveLength(1);
    const accounts = await db.select().from(authAccounts).where(eq(authAccounts.userId, "existing-user"));
    expect(accounts.map((account) => [account.providerId, account.accountId])).toEqual([["oidc", "kc-henry"]]);

    // Second sign-in reuses the link.
    const again = await signInAs(app, henry);
    expect(again.callback.headers.location).toBe("/dashboard");
    expect(await db.select().from(authAccounts)).toHaveLength(1);
  });

  it.each([
    ["false", false],
    ["the string \"true\"", "true"],
    ["missing", undefined],
  ])("refuses an email_verified claim that is %s, for an existing user and for a new one", async (_label, emailVerified) => {
    // Existing user: Better Auth's own linking gate refuses first (untrusted provider, unverified email).
    await seedExistingUser(false);
    const linkApp = buildApp({ oidc: true });
    const link = await signInAs(linkApp, { ...henry, email_verified: emailVerified });
    expect(link.callback.status).toBe(302);
    const linkLocation = new URL(link.callback.headers.location, ORIGIN);
    expect(linkLocation.pathname).toBe("/auth");
    expect(linkLocation.searchParams.get("error")).toBe("account_not_linked");
    expect(sessionCookies(link.callback)).toHaveLength(0);
    expect(await db.select().from(authAccounts)).toHaveLength(0);

    // New user with sign-up open: the OIDC validator refuses before the user row exists.
    const createApp = buildApp({ oidc: true, disableSignUp: false });
    const create = await signInAs(createApp, { ...henry, sub: "kc-new", email: "new@example.com", email_verified: emailVerified });
    expect(new URL(create.callback.headers.location, ORIGIN).searchParams.get("error")).toBe("oidc_email_not_verified");
    expect(sessionCookies(create.callback)).toHaveLength(0);
    expect(await db.select().from(authUsers)).toHaveLength(1);
    expect(await db.select().from(authAccounts)).toHaveLength(0);
  });

  it("refuses a user outside the allowed groups, also on a later sign-in after the link exists", async () => {
    await seedExistingUser(false);
    const app = buildApp({ oidc: true, allowedGroups: "atlas-admin" });
    const denied = await signInAs(app, { ...henry, groups: ["/other"] });
    expect(new URL(denied.callback.headers.location, ORIGIN).searchParams.get("error")).toBe("oidc_group_not_allowed");
    expect(sessionCookies(denied.callback)).toHaveLength(0);
    expect(await db.select().from(authAccounts)).toHaveLength(0);

    await signInAs(app, henry);
    expect(await db.select().from(authAccounts)).toHaveLength(1);
    const removed = await signInAs(app, { ...henry, groups: [] });
    expect(new URL(removed.callback.headers.location, ORIGIN).searchParams.get("error")).toBe("oidc_group_not_allowed");
    expect(sessionCookies(removed.callback)).toHaveLength(0);
  });

  it("never creates a user when sign-up is disabled", async () => {
    const app = buildApp({ oidc: true, disableSignUp: true });
    const { callback } = await signInAs(app, { ...henry, sub: "kc-stranger", email: "stranger@example.com" });
    expect(new URL(callback.headers.location, ORIGIN).pathname).toBe("/auth");
    expect(new URL(callback.headers.location, ORIGIN).searchParams.get("error")).toBeTruthy();
    expect(sessionCookies(callback)).toHaveLength(0);
    expect(await db.select().from(authUsers)).toHaveLength(0);
  });

  it("does not link to an existing password account while sign-up is open", async () => {
    await seedExistingUser(false);
    const app = buildApp({ oidc: true, disableSignUp: false });
    const { callback } = await signInAs(app, henry);
    expect(new URL(callback.headers.location, ORIGIN).searchParams.get("error")).toBe("account_not_linked");
    expect(sessionCookies(callback)).toHaveLength(0);
    expect(await db.select().from(authAccounts)).toHaveLength(0);
  });

  it("rejects a forged state and a code injected from another flow (PKCE)", async () => {
    await seedExistingUser(false);
    const app = buildApp({ oidc: true });

    const victim = request.agent(app);
    const victimStart = await begin(victim);
    const forged = await victim.get("/api/auth/callback/oidc?code=anything&state=forged-state").redirects(0);
    expect(sessionCookies(forged)).toHaveLength(0);
    expect(new URL(forged.headers.location, ORIGIN).searchParams.get("error")).toBeTruthy();

    // The attacker completes the IdP step for their own flow, then feeds that
    // code into the victim's callback with the victim's state.
    const attackerStart = await begin(request.agent(app));
    const attackerCode = idp.authorize(attackerStart.body.url, henry).code;
    const victimState = new URL(victimStart.body.url).searchParams.get("state")!;
    const injected = await victim.get(`/api/auth/callback/oidc?code=${attackerCode}&state=${encodeURIComponent(victimState)}`).redirects(0);
    expect(sessionCookies(injected)).toHaveLength(0);
    expect(new URL(injected.headers.location, ORIGIN).searchParams.get("error")).toBe("invalid_code");
    expect(idp.tokenRequests).toEqual([{ ok: false, reason: "pkce" }]);
  });

  it("refuses direct id_token sign-in, even with a valid IdP-signed token", async () => {
    await seedExistingUser(false);
    const app = buildApp({ oidc: true });
    const token = idp.idToken({ ...henry, nonce: "attacker-chosen" });
    const response = await request(app)
      .post("/api/auth/sign-in/social")
      .set("origin", ORIGIN)
      .send({ provider: "oidc", callbackURL: "/dashboard", idToken: { token, nonce: "attacker-chosen" } });
    expect(response.status).toBe(403);
    expect(response.body?.code).toBe("ID_TOKEN_SIGN_IN_DISABLED");
    expect(sessionCookies(response)).toHaveLength(0);
    expect(await db.select().from(authSessions)).toHaveLength(0);
    expect(await db.select().from(authAccounts)).toHaveLength(0);
  });

  it("refuses linking a raw id_token to a signed-in user", async () => {
    await seedExistingUser(false);
    const app = buildApp({ oidc: true });
    const { agent } = await signInAs(app, henry);
    const token = idp.idToken({ ...henry, sub: "kc-other" });
    const response = await agent
      .post("/api/auth/link-social")
      .set("origin", ORIGIN)
      .send({ provider: "oidc", callbackURL: "/", idToken: { token } });
    expect(response.status).toBe(403);
    expect(response.body?.code).toBe("ID_TOKEN_SIGN_IN_DISABLED");
    const accounts = await db.select().from(authAccounts);
    expect(accounts.map((account) => account.accountId)).toEqual(["kc-henry"]);
  });

  it.each(["https://evil.example/", "//evil.example/x", "/\\evil.example"])("refuses the off-site return URL %s", async (target) => {
    const app = buildApp({ oidc: true });
    for (const field of ["callbackURL", "errorCallbackURL"]) {
      const started = await begin(request.agent(app), { [field]: target });
      expect(started.status).toBe(403);
      expect(started.body?.url).toBeUndefined();
    }
  });

  it("keeps email/password sign-in up when discovery fails, and never logs the secret", async () => {
    const errorSpy = vi.spyOn(logger, "error");
    const app = buildApp({ oidc: true, issuer: "http://127.0.0.1:9" });
    const password = await request(app)
      .post("/api/auth/sign-in/email")
      .set("origin", ORIGIN)
      .send({ email: EXISTING_EMAIL, password: "wrong-password" });
    expect(password.status).toBe(401);
    const started = await begin(request.agent(app));
    expect(started.body?.url).toBeUndefined();
    expect(errorSpy).toHaveBeenCalled();
    expect(JSON.stringify(errorSpy.mock.calls)).not.toContain(CLIENT_SECRET);
  });
});
