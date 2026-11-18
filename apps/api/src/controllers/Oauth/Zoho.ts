import {createPublicKey, randomBytes, timingSafeEqual} from 'node:crypto';
import {Controller, Get} from '@overnightjs/core';
import type {NextFunction, Request, Response} from 'express';
import jsonwebtoken, {type JwtPayload} from 'jsonwebtoken';

import {
  API_URI,
  DASHBOARD_URI,
  DISABLE_SIGNUPS,
  ZOHO_ACCOUNTS_URL,
  ZOHO_OAUTH_CLIENT,
  ZOHO_OAUTH_ENABLED,
  ZOHO_OAUTH_SECRET,
} from '../../app/constants.js';
import {prisma} from '../../database/prisma.js';
import {redis} from '../../database/redis.js';
import {BadRequest} from '../../exceptions/index.js';
import {jwt} from '../../middleware/auth.js';
import {NtfyService} from '../../services/NtfyService.js';
import {UserService} from '../../services/UserService.js';
import {Keys} from '../../services/keys.js';
import {CatchAsync} from '../../utils/asyncHandler.js';

const STATE_COOKIE = 'zoho_oauth_state';
const NONCE_COOKIE = 'zoho_oauth_nonce';
const STATE_TTL_MS = 10 * 60 * 1000;
const ALLOWED_ZOHO_ACCOUNTS_HOSTS = new Set([
  'accounts.zoho.com',
  'accounts.zoho.in',
  'accounts.zoho.eu',
  'accounts.zoho.com.au',
  'accounts.zoho.jp',
  'accounts.zoho.ca',
  'accounts.zoho.sa',
  'accounts.zoho.com.cn',
  'accounts.zoho.com.br',
  'accounts.zoho.com.mx',
  'accounts.zoho.com.sg',
  'accounts.zoho.hk',
]);

interface ZohoOidcConfiguration {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
}

interface ZohoJwk {
  kid?: string;
  kty?: string;
  use?: string;
  alg?: string;
  n?: string;
  e?: string;
  [key: string]: unknown;
}

interface ZohoClaims extends JwtPayload {
  email?: string;
  email_verified?: boolean;
  nonce?: string;
  given_name?: string;
  family_name?: string;
  name?: string;
}

function accountBase(value: string): string | null {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || !ALLOWED_ZOHO_ACCOUNTS_HOSTS.has(url.hostname.toLowerCase())) {
      return null;
    }
    return url.origin;
  } catch {
    return null;
  }
}

function cookieOptions() {
  return {
    ...UserService.cookieOptions(new Date(Date.now() + STATE_TTL_MS)),
    sameSite: 'lax' as const,
  };
}

function clearStateCookies(res: Response) {
  const options = cookieOptions();
  res.clearCookie(STATE_COOKIE, options).clearCookie(NONCE_COOKIE, options);
}

function loginError(res: Response, message: string) {
  clearStateCookies(res);
  return res.redirect(`${DASHBOARD_URI}/auth/login?message=${encodeURIComponent(message)}`);
}

function safeEquals(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...init,
    headers: {Accept: 'application/json', ...init?.headers},
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) {
    throw new Error(`Zoho returned HTTP ${response.status}`);
  }
  return (await response.json()) as T;
}

async function verifyIdToken(idToken: string, baseUrl: string, expectedNonce: string): Promise<ZohoClaims> {
  const configuration = await fetchJson<ZohoOidcConfiguration>(`${baseUrl}/.well-known/openid-configuration`);
  const issuerUrl = new URL(configuration.issuer);
  const jwksUrl = new URL(configuration.jwks_uri);
  if (
    issuerUrl.protocol !== 'https:' ||
    jwksUrl.protocol !== 'https:' ||
    !ALLOWED_ZOHO_ACCOUNTS_HOSTS.has(issuerUrl.hostname.toLowerCase()) ||
    !ALLOWED_ZOHO_ACCOUNTS_HOSTS.has(jwksUrl.hostname.toLowerCase())
  ) {
    throw new Error('Zoho returned invalid OpenID configuration');
  }

  const decoded = jsonwebtoken.decode(idToken, {complete: true});
  if (!decoded || typeof decoded === 'string' || decoded.header.alg !== 'RS256' || !decoded.header.kid) {
    throw new Error('Zoho returned an invalid ID token');
  }

  const jwks = await fetchJson<{keys?: ZohoJwk[]}>(configuration.jwks_uri);
  const jwk = jwks.keys?.find(key => key.kid === decoded.header.kid && key.kty === 'RSA');
  if (!jwk) {
    throw new Error('Zoho signing key was not found');
  }

  const publicKey = createPublicKey({key: jwk as JsonWebKey, format: 'jwk'});
  const claims = jsonwebtoken.verify(idToken, publicKey, {
    algorithms: ['RS256'],
    audience: ZOHO_OAUTH_CLIENT,
    issuer: configuration.issuer,
  }) as ZohoClaims;

  if (claims.nonce !== expectedNonce) {
    throw new Error('Zoho ID token nonce did not match');
  }
  if (claims.email_verified !== true || typeof claims.email !== 'string' || !claims.email.trim()) {
    throw new Error('Zoho did not return a verified email address');
  }
  return claims;
}

@Controller('zoho')
export class Zoho {
  @Get('outbound')
  public sendToOutbound(_req: Request, res: Response) {
    if (!ZOHO_OAUTH_ENABLED) {
      return res.status(404).json({error: 'Zoho OAuth is not configured'});
    }

    const baseUrl = accountBase(ZOHO_ACCOUNTS_URL);
    if (!baseUrl) {
      return res.status(500).json({error: 'ZOHO_ACCOUNTS_URL is not a supported Zoho Accounts URL'});
    }

    const state = randomBytes(32).toString('base64url');
    const nonce = randomBytes(32).toString('base64url');
    const authorizeUrl = new URL('/oauth/v2/auth', baseUrl);
    authorizeUrl.search = new URLSearchParams({
      response_type: 'code',
      client_id: ZOHO_OAUTH_CLIENT,
      scope: 'openid email profile',
      redirect_uri: `${API_URI}/oauth/zoho/callback`,
      state,
      nonce,
    }).toString();

    res.cookie(STATE_COOKIE, state, cookieOptions());
    res.cookie(NONCE_COOKIE, nonce, cookieOptions());
    return res.redirect(authorizeUrl.toString());
  }

  @Get('callback')
  @CatchAsync
  public async callback(req: Request, res: Response, _next: NextFunction) {
    if (!ZOHO_OAUTH_ENABLED) {
      return res.status(404).json({error: 'Zoho OAuth is not configured'});
    }

    const state = req.query.state;
    const code = req.query.code;
    const expectedState = req.cookies?.[STATE_COOKIE];
    const expectedNonce = req.cookies?.[NONCE_COOKIE];
    const accountsServer = req.query['accounts-server'];

    if (
      typeof state !== 'string' ||
      typeof expectedState !== 'string' ||
      !safeEquals(state, expectedState) ||
      typeof expectedNonce !== 'string'
    ) {
      return loginError(res, 'Zoho sign-in could not be verified. Please try again.');
    }
    if (typeof code !== 'string' || !code) {
      return loginError(res, 'Zoho sign-in was cancelled or returned no authorization code.');
    }

    const baseUrl =
      typeof accountsServer === 'string' ? accountBase(accountsServer) || accountBase(ZOHO_ACCOUNTS_URL) : accountBase(ZOHO_ACCOUNTS_URL);
    if (!baseUrl) {
      return loginError(res, 'Zoho sign-in is not configured for this account region.');
    }

    try {
      const redirectUri = `${API_URI}/oauth/zoho/callback`;
      const tokenResponse = await fetchJson<{id_token?: string; error?: string}>(`${baseUrl}/oauth/v2/token`, {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: ZOHO_OAUTH_CLIENT,
          client_secret: ZOHO_OAUTH_SECRET,
          redirect_uri: redirectUri,
          code,
        }),
      });
      if (!tokenResponse.id_token) {
        return loginError(res, 'Zoho could not complete sign-in. Please try again.');
      }

      const claims = await verifyIdToken(tokenResponse.id_token, baseUrl, expectedNonce);
      const email = claims.email!.trim().toLowerCase();
      let user = await UserService.email(email);
      let isNewUser = false;

      if (!user) {
        if (DISABLE_SIGNUPS) {
          throw new BadRequest('New user signups are currently disabled');
        }
        user = await prisma.user.create({
          data: {email, type: 'ZOHO_OAUTH', emailVerified: true},
        });
        isNewUser = true;
      } else if (!user.emailVerified) {
        // Zoho has already verified this exact address, so existing local accounts can be linked.
        user = await prisma.user.update({where: {id: user.id}, data: {emailVerified: true}});
        await Promise.all([redis.del(Keys.User.id(user.id)), redis.del(Keys.User.email(email))]);
      }

      if (isNewUser) {
        await NtfyService.notifyUserOAuthSignup(user.email, user.id, 'Zoho');
      }

      const token = jwt.sign(user.id);
      clearStateCookies(res);
      return res.cookie(UserService.COOKIE_NAME, token, UserService.cookieOptions()).redirect(DASHBOARD_URI);
    } catch (error) {
      if (error instanceof BadRequest) {
        return loginError(res, error.message);
      }
      return loginError(res, 'Zoho sign-in failed. Please try again.');
    }
  }
}
