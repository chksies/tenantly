import { createRemoteJWKSet, jwtVerify } from 'jose';
import { config } from '../../config.js';

export interface OAuthProfile {
  subject: string;
  email: string;
  emailVerified: boolean;
  name: string;
}

/** A pluggable OAuth2 / OpenID Connect identity provider (authorization code flow with PKCE). */
export interface OAuthProvider {
  name: string;
  authorizationUrl(p: { state: string; codeChallenge: string; redirectUri: string }): string;
  exchange(p: { code: string; codeVerifier: string; redirectUri: string }): Promise<OAuthProfile>;
}

export function googleProvider(clientId: string, clientSecret: string): OAuthProvider {
  const jwks = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'));
  return {
    name: 'google',
    authorizationUrl({ state, codeChallenge, redirectUri }) {
      const u = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      u.search = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        prompt: 'select_account',
      }).toString();
      return u.toString();
    },
    async exchange({ code, codeVerifier, redirectUri }) {
      const res = await fetch('https://oauth2.googleapis.com/token', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code, code_verifier: codeVerifier, redirect_uri: redirectUri,
          client_id: clientId, client_secret: clientSecret, grant_type: 'authorization_code',
        }),
      });
      if (!res.ok) throw new Error(`Google token exchange failed (${res.status})`);
      const { id_token } = (await res.json()) as { id_token?: string };
      if (!id_token) throw new Error('Google response had no id_token');
      // Signature, expiry, issuer and audience are all verified against Google's published keys.
      const { payload } = await jwtVerify(id_token, jwks, {
        issuer: ['https://accounts.google.com', 'accounts.google.com'],
        audience: clientId,
      });
      return {
        subject: String(payload.sub),
        email: String(payload.email),
        emailVerified: payload.email_verified === true,
        name: String(payload.name ?? payload.email),
      };
    },
  };
}

export function defaultOAuthProviders(): Record<string, OAuthProvider> {
  const providers: Record<string, OAuthProvider> = {};
  if (config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET) {
    providers.google = googleProvider(config.GOOGLE_CLIENT_ID, config.GOOGLE_CLIENT_SECRET);
  }
  return providers;
}
