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
  ZOHO_OIDC_DISCOVERY_URL,
} from '../../app/constants.js';
import {prisma} from '../../database/prisma.js';
import {redis} from '../../database/redis.js';
import {BadRequest} from '../../exceptions/index.js';
import {jwt} from '../../middleware/auth.js';
import {NtfyService} from '../../services/NtfyService.js';
import {UserService} from '../../services/UserService.js';
import {Keys} from '../../services/keys.js';
import {CatchAsync} from '../../utils/asyncHandler.js';
import {logger} from '../../utils/logger.js';

const STATE_COOKIE = 'zoho_oauth_state';
const NONCE_COOKIE = 'zoho_oauth_nonce';
const STATE_TTL_MS = 10 * 60 * 1000;
const ALLOWED_ZOHO_DIRECTORY_HOSTS = new Set(['directory.zoho.com']);
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
  userinfo_endpoint: string;
  jwks_uri: string;
}

interface ZohoJwk {
  kid?: string;
  key_id?: string;
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

interface ZohoUserInfo {
  sub?: string;
  email?: string;
  email_verified?: boolean;
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

function allowedHttpsUrl(value: string, hosts: Set<string>): URL | null {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && hosts.has(url.hostname.toLowerCase()) ? url : null;
  } catch {
    return null;
  }
}

async function oidcConfiguration(accountsBase: string): Promise<ZohoOidcConfiguration> {
  const directoryMode = ZOHO_OIDC_DISCOVERY_URL !== '';
  const discoveryUrl = directoryMode ? ZOHO_OIDC_DISCOVERY_URL : `${accountsBase}/.well-known/openid-configuration`;
  if (
    directoryMode
      ? !allowedHttpsUrl(discoveryUrl, ALLOWED_ZOHO_DIRECTORY_HOSTS)
      : !allowedHttpsUrl(discoveryUrl, ALLOWED_ZOHO_ACCOUNTS_HOSTS)
  ) {
    throw new Error('Zoho returned invalid OpenID configuration');
  }

  const configuration = await fetchJson<ZohoOidcConfiguration>(discoveryUrl);
  const issuerHosts = ALLOWED_ZOHO_ACCOUNTS_HOSTS;
  const endpointHosts = directoryMode ? ALLOWED_ZOHO_DIRECTORY_HOSTS : ALLOWED_ZOHO_ACCOUNTS_HOSTS;
  if (
    !allowedHttpsUrl(configuration.issuer, issuerHosts) ||
    !allowedHttpsUrl(configuration.authorization_endpoint, endpointHosts) ||
    !allowedHttpsUrl(configuration.token_endpoint, endpointHosts) ||
    !allowedHttpsUrl(configuration.userinfo_endpoint, endpointHosts) ||
    !allowedHttpsUrl(configuration.jwks_uri, endpointHosts)
  ) {
    throw new Error('Zoho returned invalid OpenID configuration');
  }
  return configuration;
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

async function verifyIdToken(
  idToken: string,
  configuration: ZohoOidcConfiguration,
  expectedNonce: string,
): Promise<ZohoClaims> {
  const decoded = jsonwebtoken.decode(idToken, {complete: true});
  const headerKeyId =
    decoded && typeof decoded !== 'string'
      ? typeof decoded.header.kid === 'string'
        ? decoded.header.kid
        : typeof (decoded.header as typeof decoded.header & {key_id?: string}).key_id === 'string'
          ? (decoded.header as typeof decoded.header & {key_id?: string}).key_id
          : undefined
      : undefined;
  if (!decoded || typeof decoded === 'string' || decoded.header.alg !== 'RS256' || !headerKeyId) {
    throw new Error('Zoho returned an invalid ID token');
  }

  const jwks = await fetchJson<{keys?: ZohoJwk[]}>(configuration.jwks_uri);
  const rsaKeys = (jwks.keys ?? []).filter(
    key => key.kty === 'RSA' && (!key.alg || key.alg === 'RS256') && (!key.use || key.use === 'sig'),
  );
  const matchingKeys = rsaKeys.filter(key => key.kid === headerKeyId || key.key_id === headerKeyId);
  const candidateKeys = matchingKeys.length > 0 ? matchingKeys : rsaKeys;
  if (candidateKeys.length === 0) {
    throw new Error('Zoho signing key was not found');
  }

  let claims: ZohoClaims | undefined;
  let verificationError: unknown;
  for (const jwk of candidateKeys) {
    try {
      const publicKey = createPublicKey({
        key: jwk as unknown as import('node:crypto').JsonWebKey,
        format: 'jwk',
      });
      claims = jsonwebtoken.verify(idToken, publicKey, {
        algorithms: ['RS256'],
        audience: ZOHO_OAUTH_CLIENT,
        issuer: configuration.issuer,
      }) as ZohoClaims;
      break;
    } catch (error) {
      verificationError = error;
    }
  }
  if (!claims) {
    throw verificationError instanceof Error ? verificationError : new Error('Zoho ID token signature could not be verified');
  }

  if (claims.nonce !== expectedNonce) {
    throw new Error('Zoho ID token nonce did not match');
  }
  return claims;
}

@Controller('zoho')
export class Zoho {
  @Get('outbound')
  @CatchAsync
  public async sendToOutbound(_req: Request, res: Response) {
    if (!ZOHO_OAUTH_ENABLED) {
      return res.status(404).json({error: 'Zoho OAuth is not configured'});
    }

    const baseUrl = accountBase(ZOHO_ACCOUNTS_URL);
    if (!baseUrl) {
      return res.status(500).json({error: 'ZOHO_ACCOUNTS_URL is not a supported Zoho Accounts URL'});
    }

    const configuration = await oidcConfiguration(baseUrl);

    const state = randomBytes(32).toString('base64url');
    const nonce = randomBytes(32).toString('base64url');
    const authorizeUrl = new URL(configuration.authorization_endpoint);
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

    const baseUrl = ZOHO_OIDC_DISCOVERY_URL
      ? accountBase(ZOHO_ACCOUNTS_URL)
      : typeof accountsServer === 'string'
        ? accountBase(accountsServer) || accountBase(ZOHO_ACCOUNTS_URL)
        : accountBase(ZOHO_ACCOUNTS_URL);
    if (!baseUrl) {
      return loginError(res, 'Zoho sign-in is not configured for this account region.');
    }

    let stage = 'oidc_discovery';
    try {
      const configuration = await oidcConfiguration(baseUrl);
      stage = 'token_exchange';
      const redirectUri = `${API_URI}/oauth/zoho/callback`;
      const tokenResponse = await fetchJson<{id_token?: string; access_token?: string; error?: string}>(configuration.token_endpoint, {
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
        const providerError = tokenResponse.error;
        const safeProviderError =
          typeof providerError === 'string' && /^[a-zA-Z0-9_-]{1,80}$/.test(providerError)
            ? providerError
            : 'unrecognized';
        logger.warn(`Zoho OAuth token response did not include an ID token (${safeProviderError})`, undefined, res);
        return loginError(res, 'Zoho could not complete sign-in. Please try again.');
      }

      stage = 'id_token_verification';
      const claims = await verifyIdToken(tokenResponse.id_token, configuration, expectedNonce);
      stage = 'userinfo_lookup';
      if (!tokenResponse.access_token) {
        throw new Error('Zoho token response did not include an access token');
      }
      const userInfo = await fetchJson<ZohoUserInfo>(configuration.userinfo_endpoint, {
        headers: {Authorization: `Bearer ${tokenResponse.access_token}`},
      });
      if (typeof claims.sub !== 'string' || !claims.sub || userInfo.sub !== claims.sub) {
        throw new Error('Zoho userinfo subject did not match the ID token');
      }
      if (claims.email && userInfo.email && claims.email.toLowerCase() !== userInfo.email.toLowerCase()) {
        throw new Error('Zoho userinfo email did not match the ID token');
      }
      const verifiedEmail = userInfo.email ?? claims.email;
      const isEmailVerified = userInfo.email_verified === true || claims.email_verified === true;
      if (!isEmailVerified || typeof verifiedEmail !== 'string' || !verifiedEmail.trim()) {
        throw new Error('Zoho did not return a verified email address');
      }
      const email = verifiedEmail.trim().toLowerCase();
      stage = 'user_lookup';
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

      stage = 'session_creation';
      const token = jwt.sign(user.id);
      clearStateCookies(res);
      return res.cookie(UserService.COOKIE_NAME, token, UserService.cookieOptions()).redirect(DASHBOARD_URI);
    } catch (error) {
      const safeErrors = new Set([
        'Zoho returned invalid OpenID configuration',
        'Zoho returned an invalid ID token',
        'Zoho signing key was not found',
        'Zoho ID token nonce did not match',
        'Zoho did not return a verified email address',
        'Zoho token response did not include an access token',
        'Zoho userinfo subject did not match the ID token',
        'Zoho userinfo email did not match the ID token',
      ]);
      const safeReason =
        error instanceof Error && (safeErrors.has(error.message) || /^Zoho returned HTTP \d{3}$/.test(error.message))
          ? error.message
          : error instanceof Error
            ? error.name
            : typeof error;
      logger.error(`Zoho OAuth callback failed at ${stage} (${safeReason})`, undefined, undefined, res);
      if (error instanceof BadRequest) {
        return loginError(res, error.message);
      }
      return loginError(res, 'Zoho sign-in failed. Please try again.');
    }
  }
}
