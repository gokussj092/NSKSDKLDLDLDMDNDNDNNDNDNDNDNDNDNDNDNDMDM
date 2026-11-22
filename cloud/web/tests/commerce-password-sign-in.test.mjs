import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {test} from 'node:test';
import {PGlite} from '@electric-sql/pglite';
import {getMigrations} from 'better-auth/db/migration';
import {Pool} from 'pg';
import {PATCH as setPassword} from '../app/api/account/password/route.js';
import {POST as handleAuth} from '../app/api/auth/[...all]/route.js';
import {makeAuth} from '../lib/commerce/auth.mjs';

test('a Google-linked account can sign out and sign in with its saved password', async t => {
  const origin = 'http://localhost:3000';
  const env = {
    NODE_ENV: 'test',
    CLOUD_SITE_PUBLIC_ORIGIN: origin,
    SPDECODE_ACCOUNTS_ENABLED: 'true',
    SPDECODE_DATABASE_URL: 'postgres://synthetic-only',
    BETTER_AUTH_SECRET: 'synthetic-password-test-secret'.repeat(2),
    GOOGLE_CLIENT_ID: 'synthetic.apps.googleusercontent.com',
    GOOGLE_CLIENT_SECRET: 'synthetic-only',
  };
  Object.assign(process.env, env);

  const embedded = new PGlite();
  t.after(() => embedded.close());
  const query = async (sql, params = []) => {
    const result = await embedded.query(sql, params);
    return {rows: result.rows, rowCount: result.affectedRows ?? result.rows.length};
  };
  const connect = async () => ({query, release() {}});
  t.mock.method(Pool.prototype, 'query', query);
  t.mock.method(Pool.prototype, 'connect', connect);
  const auth = makeAuth({query, connect}, env);
  await (await getMigrations(auth.options)).runMigrations();

  const email = 'review.signin+qa@example.invalid';
  const password = 'Synthetic-only-Password37';
  const userId = randomUUID();
  await query('INSERT INTO shop_user (id,name,email,"emailVerified","createdAt","updatedAt") VALUES ($1,$2,$3,true,now(),now())',
    [userId, 'Synthetic reviewer', email]);
  const {internalAdapter} = await auth.$context;
  await internalAdapter.linkAccount({userId, providerId: 'google', accountId: 'synthetic-google-subject'});
  const googleSession = await internalAdapter.createSession(userId);

  function request(path, body, {method = 'POST', token} = {}) {
    const headers = new Headers({Origin: origin, 'Content-Type': 'application/json'});
    if (token) headers.set('Authorization', `Bearer ${token}`);
    return new Request(origin + path, {method, headers, body: JSON.stringify(body)});
  }

  const saved = await setPassword(request('/api/account/password', {newPassword: password},
    {method: 'PATCH', token: googleSession.token}));
  assert.equal(saved.status, 200);
  assert.equal((await saved.json()).passwordEnabled, true);
  assert.equal((await handleAuth(request('/api/auth/sign-out', {}, {token: googleSession.token}))).status, 200);

  const signIn = (address, input) => handleAuth(request('/api/auth/sign-in/email',
    {email: address, password: input, rememberMe: true}));
  const signedIn = await signIn(email, password);
  assert.equal(signedIn.status, 200);
  assert.equal((await signedIn.json()).user.id, userId);
  assert.ok(signedIn.headers.get('set-auth-token'));
  assert.equal((await signIn(email, 'Incorrect-synthetic-password')).status, 401);
  assert.equal((await signIn('missing-domain', password)).status, 400);
});
