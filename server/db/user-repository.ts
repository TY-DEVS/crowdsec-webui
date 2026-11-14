import crypto from 'node:crypto';
import {
  INITIAL_OIDC_LOGOUT_VERSION,
  type AuthUserListRow,
  type AuthUserRow,
  type CountRow,
  type Database,
  type OidcLinkMethod,
  type OidcUserUpsertParams,
  type SqliteStatement,
  type WebAuthnCredentialRow,
} from './types';

export interface UserRepositoryHooks {
  revokeOidcSession?: (issuer: string, sessionId: string, expiresAt: number) => void;
  revokeOidcUserSessions?: (issuer: string, subject: string) => boolean;
  bumpOidcLogoutVersion?: (issuer: string, subject: string) => void;
}

export class UserRepository {
  private readonly countAuthUsersStatement: SqliteStatement;
  private readonly createAuthUserStatement: SqliteStatement;
  private readonly getAuthUserByIdStatement: SqliteStatement;
  private readonly getAuthUserByUsernameStatement: SqliteStatement;
  private readonly getAuthUserByOidcIdentityStatement: SqliteStatement;
  private readonly updateAuthUserPasswordStatement: SqliteStatement;
  private readonly updateAuthUserTotpStatement: SqliteStatement;
  private readonly updateAuthUserTotpLastStepStatement: SqliteStatement;
  private readonly createOidcUserStatement: SqliteStatement;
  private readonly updateOidcUserStatement: SqliteStatement;
  private readonly revokeOidcUserSessionsStatement: SqliteStatement;
  private readonly denyOidcIdentityStatement: SqliteStatement;
  private readonly insertRevokedOidcSessionStatement: SqliteStatement;
  private readonly pruneRevokedOidcSessionsStatement: SqliteStatement;
  private readonly getRevokedOidcSessionStatement: SqliteStatement;
  private readonly insertRevokedAuthSessionStatement: SqliteStatement;
  private readonly pruneRevokedAuthSessionsStatement: SqliteStatement;
  private readonly getRevokedAuthSessionStatement: SqliteStatement;
  private readonly insertProcessedOidcLogoutStatement: SqliteStatement;
  private readonly pruneProcessedOidcLogoutsStatement: SqliteStatement;
  private readonly bumpOidcLogoutVersionStatement: SqliteStatement;
  private readonly getOidcLogoutVersionStatement: SqliteStatement;
  private readonly listWebAuthnCredentialsByUserStatement: SqliteStatement;
  private readonly countWebAuthnCredentialsStatement: SqliteStatement;
  private readonly createWebAuthnCredentialStatement: SqliteStatement;
  private readonly getWebAuthnCredentialByCredentialIdStatement: SqliteStatement;
  private readonly updateWebAuthnCredentialCounterStatement: SqliteStatement;
  private readonly renameWebAuthnCredentialStatement: SqliteStatement;
  private readonly deleteWebAuthnCredentialStatement: SqliteStatement;

  constructor(
    private readonly db: Database,
    stateQuery: (sql: string) => SqliteStatement,
    private readonly hooks?: UserRepositoryHooks,
  ) {
    this.countAuthUsersStatement = stateQuery('SELECT COUNT(*) as count FROM auth_users');
    this.createAuthUserStatement = stateQuery(`
      INSERT INTO auth_users (username, password_hash, role, auth_provider, password_change_required, oidc_auto_link_blocked, created_at, updated_at)
      VALUES ($username, $password_hash, $role, $auth_provider, $password_change_required, $oidc_auto_link_blocked, $created_at, $updated_at)
    `);
    this.getAuthUserByIdStatement = stateQuery('SELECT * FROM auth_users WHERE id = $id');
    this.getAuthUserByUsernameStatement = stateQuery('SELECT * FROM auth_users WHERE username = $username');
    this.getAuthUserByOidcIdentityStatement = stateQuery(`
      SELECT * FROM auth_users
      WHERE oidc_issuer = $oidc_issuer AND oidc_subject = $oidc_subject
    `);
    this.updateAuthUserPasswordStatement = stateQuery(`
      UPDATE auth_users
      SET password_hash = $password_hash,
          password_change_required = 0,
          session_version = session_version + 1,
          updated_at = $updated_at
      WHERE id = $id
    `);
    this.updateAuthUserTotpStatement = stateQuery(`
      UPDATE auth_users
      SET totp_secret = $totp_secret,
          totp_enabled = $totp_enabled,
          totp_last_step = $totp_last_step,
          session_version = session_version + 1,
          updated_at = $updated_at
      WHERE id = $id
    `);
    this.updateAuthUserTotpLastStepStatement = stateQuery(`
      UPDATE auth_users
      SET totp_last_step = $totp_last_step, updated_at = $updated_at
      WHERE id = $id AND (totp_last_step IS NULL OR totp_last_step < $totp_last_step)
    `);
    this.createOidcUserStatement = stateQuery(`
      INSERT INTO auth_users (
        username, password_hash, role, auth_provider, oidc_issuer, oidc_subject, created_at, updated_at
      )
      VALUES ($username, NULL, $role, 'oidc', $oidc_issuer, $oidc_subject, $created_at, $updated_at)
    `);
    this.updateOidcUserStatement = stateQuery(`
      UPDATE auth_users
      SET username = $username,
          role = $role,
          auth_provider = 'oidc',
          oidc_issuer = $oidc_issuer,
          oidc_subject = $oidc_subject,
          session_version = CASE WHEN role IS NOT $role THEN session_version + 1 ELSE session_version END,
          updated_at = $updated_at
      WHERE id = $id
    `);
    this.revokeOidcUserSessionsStatement = stateQuery(`
      UPDATE auth_users
      SET session_version = session_version + CASE WHEN oidc_linked_at IS NULL THEN 1 ELSE 0 END,
          oidc_session_version = oidc_session_version + CASE WHEN oidc_linked_at IS NULL THEN 0 ELSE 1 END,
          updated_at = $updated_at
      WHERE oidc_issuer = $oidc_issuer AND oidc_subject = $oidc_subject
    `);
    this.denyOidcIdentityStatement = stateQuery(`
      UPDATE auth_users
      SET role = CASE WHEN COALESCE(password_hash, '') = '' THEN 'read-only' ELSE role END,
          oidc_role = NULL,
          session_version = session_version + CASE WHEN oidc_linked_at IS NULL THEN 1 ELSE 0 END,
          oidc_session_version = oidc_session_version + CASE WHEN oidc_linked_at IS NULL THEN 0 ELSE 1 END,
          updated_at = $updated_at
      WHERE oidc_issuer = $oidc_issuer AND oidc_subject = $oidc_subject
    `);
    this.insertRevokedOidcSessionStatement = stateQuery(`
      INSERT OR REPLACE INTO oidc_revoked_sessions (issuer, session_id, expires_at)
      VALUES ($issuer, $session_id, $expires_at)
    `);
    this.pruneRevokedOidcSessionsStatement = stateQuery('DELETE FROM oidc_revoked_sessions WHERE expires_at <= $now');
    this.getRevokedOidcSessionStatement = stateQuery(`
      SELECT 1 FROM oidc_revoked_sessions
      WHERE issuer = $issuer AND session_id = $session_id AND expires_at > $now
    `);
    this.insertRevokedAuthSessionStatement = stateQuery(`
      INSERT OR REPLACE INTO revoked_auth_sessions (session_id, expires_at)
      VALUES ($session_id, $expires_at)
    `);
    this.pruneRevokedAuthSessionsStatement = stateQuery('DELETE FROM revoked_auth_sessions WHERE expires_at <= $now');
    this.getRevokedAuthSessionStatement = stateQuery(`
      SELECT 1 FROM revoked_auth_sessions
      WHERE session_id = $session_id AND expires_at > $now
    `);
    this.insertProcessedOidcLogoutStatement = stateQuery(`
      INSERT OR IGNORE INTO oidc_processed_logouts (issuer, token_id, expires_at)
      VALUES ($issuer, $token_id, $expires_at)
    `);
    this.pruneProcessedOidcLogoutsStatement = stateQuery('DELETE FROM oidc_processed_logouts WHERE expires_at <= $now');
    this.bumpOidcLogoutVersionStatement = stateQuery(`
      INSERT INTO oidc_logout_versions (issuer, subject, version)
      SELECT $issuer, $subject, ${INITIAL_OIDC_LOGOUT_VERSION + 1}
      WHERE EXISTS (SELECT 1 FROM auth_users WHERE oidc_issuer = $issuer AND oidc_subject = $subject)
      ON CONFLICT (issuer, subject) DO UPDATE SET version = version + 1
    `);
    this.getOidcLogoutVersionStatement = stateQuery(`
      SELECT version FROM oidc_logout_versions WHERE issuer = $issuer AND subject = $subject
    `);
    this.listWebAuthnCredentialsByUserStatement = stateQuery(`
      SELECT * FROM webauthn_credentials
      WHERE user_id = $user_id
      ORDER BY created_at DESC
    `);
    this.countWebAuthnCredentialsStatement = stateQuery(`
      SELECT COUNT(*) as count
      FROM webauthn_credentials credentials
      JOIN auth_users users ON users.id = credentials.user_id
      WHERE users.disabled = 0 AND (users.auth_provider <> 'oidc' OR users.password_hash IS NOT NULL)
    `);
    this.createWebAuthnCredentialStatement = stateQuery(`
      INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, transports, name, created_at)
      VALUES ($user_id, $credential_id, $public_key, $sign_count, $transports, $name, $created_at)
    `);
    this.getWebAuthnCredentialByCredentialIdStatement = stateQuery('SELECT * FROM webauthn_credentials WHERE credential_id = $credential_id');
    this.updateWebAuthnCredentialCounterStatement = stateQuery(`
      UPDATE webauthn_credentials
      SET sign_count = $sign_count
      WHERE id = $id
    `);
    this.renameWebAuthnCredentialStatement = stateQuery(`
      UPDATE webauthn_credentials
      SET name = $name
      WHERE id = $id AND user_id = $user_id
    `);
    this.deleteWebAuthnCredentialStatement = stateQuery('DELETE FROM webauthn_credentials WHERE id = $id AND user_id = $user_id');
  }

  countAuthUsers(): number {
    return (this.countAuthUsersStatement.get() as CountRow).count;
  }

  createAuthUser(params: {
    username: string;
    passwordHash: string | null;
    role: 'admin' | 'read-only';
    authProvider: 'password' | 'oidc';
    passwordChangeRequired?: boolean;
    oidcAutoLinkBlocked?: boolean;
  }): number {
    const now = new Date().toISOString();
    const result = this.createAuthUserStatement.run({
      $username: params.username,
      $password_hash: params.passwordHash,
      $role: params.role,
      $auth_provider: params.authProvider,
      $password_change_required: params.passwordChangeRequired ? 1 : 0,
      $oidc_auto_link_blocked: params.oidcAutoLinkBlocked ? 1 : 0,
      $created_at: now,
      $updated_at: now,
    }) as { lastInsertRowid?: number | bigint };
    return Number(result.lastInsertRowid);
  }

  getAuthUserById(id: number): AuthUserRow | null {
    return (this.getAuthUserByIdStatement.get({ $id: id }) as AuthUserRow | null) || null;
  }

  getAuthUserByUsername(username: string): AuthUserRow | null {
    return (this.getAuthUserByUsernameStatement.get({ $username: username }) as AuthUserRow | null) || null;
  }

  getAuthUserByOidcIdentity(issuer: string, subject: string): AuthUserRow | null {
    return (this.getAuthUserByOidcIdentityStatement.get({
      $oidc_issuer: issuer,
      $oidc_subject: subject,
    }) as AuthUserRow | null) || null;
  }

  updateAuthUserPassword(id: number, passwordHash: string): boolean {
    return this.updateAuthUserPasswordStatement.run({
      $id: id,
      $password_hash: passwordHash,
      $updated_at: new Date().toISOString(),
    }).changes > 0;
  }

  listAuthUsers(): AuthUserListRow[] {
    return this.db.prepare(`
      SELECT users.*, (SELECT COUNT(*) FROM webauthn_credentials credentials WHERE credentials.user_id = users.id) AS passkey_count
      FROM auth_users users
      ORDER BY users.username COLLATE NOCASE, users.id
    `).all() as AuthUserListRow[];
  }

  /** Counts administrators who can still sign in, optionally leaving one account out. */
  countActiveAdmins(excludingId?: number): number {
    return (this.db.prepare(`
      SELECT COUNT(*) AS count FROM auth_users WHERE role = 'admin' AND disabled = 0 AND id <> ?
    `).get(excludingId ?? -1) as CountRow).count;
  }

  updateAuthUserRole(id: number, role: 'admin' | 'read-only'): boolean {
    return this.db.prepare('UPDATE auth_users SET role = ?, updated_at = ? WHERE id = ?')
      .run(role, new Date().toISOString(), id).changes > 0;
  }

  /** Disabling an account also ends its sessions. */
  setAuthUserDisabled(id: number, disabled: boolean): boolean {
    return this.db.prepare(`
      UPDATE auth_users
      SET disabled = ?,
          session_version = CASE WHEN ? = 1 THEN session_version + 1 ELSE session_version END,
          updated_at = ?
      WHERE id = ?
    `).run(disabled ? 1 : 0, disabled ? 1 : 0, new Date().toISOString(), id).changes > 0;
  }

  /** Sets a password chosen by an administrator and ends the account's sessions. */
  resetAuthUserPassword(id: number, passwordHash: string, changeRequired: boolean): boolean {
    return this.db.prepare(`
      UPDATE auth_users
      SET password_hash = ?, password_change_required = ?, session_version = session_version + 1, updated_at = ?
      WHERE id = ?
    `).run(passwordHash, changeRequired ? 1 : 0, new Date().toISOString(), id).changes > 0;
  }

  /** Removes the account's TOTP secret and passkeys and ends its sessions. */
  resetAuthUserSecondFactors(id: number): boolean {
    return this.db.transaction(() => {
      this.db.prepare('DELETE FROM webauthn_credentials WHERE user_id = ?').run(id);
      return this.db.prepare(`
        UPDATE auth_users
        SET totp_secret = NULL, totp_enabled = 0, totp_last_step = NULL, session_version = session_version + 1, updated_at = ?
        WHERE id = ?
      `).run(new Date().toISOString(), id).changes > 0;
    })();
  }

  /** Deletes an account together with its passkeys, preferences and saved search filters. */
  deleteAuthUser(id: number): boolean {
    return this.db.transaction(() => {
      this.db.prepare('DELETE FROM webauthn_credentials WHERE user_id = ?').run(id);
      this.db.prepare('DELETE FROM user_preferences WHERE user_id = ?').run(id);
      this.db.prepare('DELETE FROM saved_search_filters WHERE owner_id = ?').run(id);
      this.db.prepare('DELETE FROM recent_search_filters WHERE owner_id = ?').run(id);
      return this.db.prepare('DELETE FROM auth_users WHERE id = ?').run(id).changes > 0;
    })();
  }

  getUserPreferences(userId: number): Record<string, string> {
    const rows = this.db.prepare('SELECT key, value FROM user_preferences WHERE user_id = ?').all(userId) as Array<{ key: string; value: string }>;
    return Object.fromEntries(rows.map((row) => [row.key, row.value]));
  }

  setUserPreference(userId: number, key: string, value: string): void {
    this.db.prepare(`
      INSERT INTO user_preferences (user_id, key, value) VALUES (?, ?, ?)
      ON CONFLICT (user_id, key) DO UPDATE SET value = excluded.value
    `).run(userId, key, value);
  }

  updateAuthUserTotp(id: number, secret: string | null, enabled: boolean): boolean {
    return this.updateAuthUserTotpStatement.run({
      $id: id,
      $totp_secret: secret,
      $totp_enabled: enabled ? 1 : 0,
      $totp_last_step: null,
      $updated_at: new Date().toISOString(),
    }).changes > 0;
  }

  updateAuthUserTotpLastStep(id: number, lastStep: number): boolean {
    return this.updateAuthUserTotpLastStepStatement.run({
      $id: id,
      $totp_last_step: lastStep,
      $updated_at: new Date().toISOString(),
    }).changes > 0;
  }

  upsertOidcUser(params: OidcUserUpsertParams): AuthUserRow {
    const now = new Date().toISOString();
    let user = this.getAuthUserByOidcIdentity(params.issuer, params.subject);

    // A linked account keeps its local username, role and sessions.
    if (user?.oidc_linked_at) {
      this.db.query(`
        UPDATE auth_users
        SET oidc_username = $username,
            oidc_role = $role,
            oidc_session_version = CASE WHEN oidc_role IS NOT $role THEN oidc_session_version + 1 ELSE oidc_session_version END,
            updated_at = $updated_at
        WHERE id = $id
      `).run({ $id: user.id, $username: params.username, $role: params.role, $updated_at: now });
      return this.getAuthUserById(user.id)!;
    }

    if (!user) {
      const legacy = this.getAuthUserByUsername(params.username);
      if (legacy?.auth_provider === 'oidc' && !legacy.oidc_subject && !legacy.password_hash) {
        user = legacy;
      }
    }

    const usernameOwner = this.getAuthUserByUsername(params.username);
    const identitySuffix = crypto
      .createHash('sha256')
      .update(`${params.issuer}\n${params.subject}`, 'utf8')
      .digest('hex')
      .slice(0, 10);
    const storedUsername = !usernameOwner || usernameOwner.id === user?.id
      ? params.username
      : `${params.username}#oidc-${identitySuffix}`;

    if (!user) {
      const result = this.createOidcUserStatement.run({
        $username: storedUsername,
        $role: params.role,
        $oidc_issuer: params.issuer,
        $oidc_subject: params.subject,
        $created_at: now,
        $updated_at: now,
      }) as { lastInsertRowid?: number | bigint };
      return this.getAuthUserById(Number(result.lastInsertRowid))!;
    }

    this.updateOidcUserStatement.run({
      $id: user.id,
      $username: storedUsername,
      $role: params.role,
      $oidc_issuer: params.issuer,
      $oidc_subject: params.subject,
      $updated_at: now,
    });
    return this.getAuthUserById(user.id)!;
  }

  findOidcAutoLinkTarget(username: string): AuthUserRow | null {
    const user = this.getAuthUserByUsername(username);
    return user?.password_hash && !user.disabled && !user.oidc_auto_link_blocked && !user.oidc_subject ? user : null;
  }

  linkOidcIdentity(userId: number, identity: OidcUserUpsertParams, method: OidcLinkMethod): boolean {
    return this.db.transaction(() => {
      const target = this.getAuthUserById(userId);
      if (!target?.password_hash || target.oidc_linked_at) return false;

      const owner = this.getAuthUserByOidcIdentity(identity.issuer, identity.subject);
      if (owner && owner.id !== target.id) {
        if (owner.password_hash || owner.disabled) return false;
        this.db.prepare('UPDATE OR IGNORE saved_search_filters SET owner_id = ? WHERE owner_id = ?').run(target.id, owner.id);
        this.deleteAuthUser(owner.id);
      }

      const now = new Date().toISOString();
      this.db.query(`
        UPDATE auth_users
        SET auth_provider = 'oidc',
            oidc_issuer = $issuer,
            oidc_subject = $subject,
            oidc_username = $username,
            oidc_role = $role,
            oidc_linked_at = $now,
            oidc_link_method = $method,
            oidc_auto_link_blocked = 0,
            session_version = session_version + $session_bump,
            updated_at = $now
        WHERE id = $id
      `).run({
        $id: target.id,
        $issuer: identity.issuer,
        $subject: identity.subject,
        $username: identity.username,
        $role: identity.role,
        $now: now,
        $method: method,
        $session_bump: method === 'verified' ? 1 : 0,
      });
      return true;
    })();
  }

  unlinkOidcIdentity(userId: number): boolean {
    return this.db.prepare(`
      UPDATE auth_users
      SET auth_provider = 'password',
          oidc_issuer = NULL,
          oidc_subject = NULL,
          oidc_username = NULL,
          oidc_role = NULL,
          oidc_linked_at = NULL,
          oidc_link_method = NULL,
          oidc_auto_link_blocked = 1,
          session_version = session_version + 1,
          updated_at = ?
      WHERE id = ?
    `).run(new Date().toISOString(), userId).changes > 0;
  }

  applyOidcLogout(params: {
    issuer: string;
    subject?: string;
    sessionId?: string;
    tokenId: string;
    tokenExpiresAt: number;
    sessionExpiresAt: number;
  }): void {
    this.db.transaction(() => {
      this.pruneProcessedOidcLogoutsStatement.run({ $now: Math.floor(Date.now() / 1000) });
      const inserted = this.insertProcessedOidcLogoutStatement.run({
        $issuer: params.issuer,
        $token_id: params.tokenId,
        $expires_at: params.tokenExpiresAt,
      });
      if (!inserted.changes) return;

      if (params.sessionId) {
        if (this.hooks?.revokeOidcSession) {
          this.hooks.revokeOidcSession(params.issuer, params.sessionId, params.sessionExpiresAt);
        } else {
          this.revokeOidcSession(params.issuer, params.sessionId, params.sessionExpiresAt);
        }
        if (params.subject) {
          if (this.hooks?.bumpOidcLogoutVersion) {
            this.hooks.bumpOidcLogoutVersion(params.issuer, params.subject);
          } else {
            this.bumpOidcLogoutVersion(params.issuer, params.subject);
          }
        }
      } else if (params.subject) {
        if (this.hooks?.revokeOidcUserSessions) {
          this.hooks.revokeOidcUserSessions(params.issuer, params.subject);
        } else {
          this.revokeOidcUserSessions(params.issuer, params.subject);
        }
      } else {
        throw new Error('OIDC logout requires a subject or session ID');
      }
    })();
  }

  revokeOidcUserSessions(issuer: string, subject: string): boolean {
    return this.revokeOidcUserSessionsStatement.run({
      $oidc_issuer: issuer,
      $oidc_subject: subject,
      $updated_at: new Date().toISOString(),
    }).changes > 0;
  }

  denyOidcIdentity(issuer: string, subject: string): boolean {
    return this.denyOidcIdentityStatement.run({
      $oidc_issuer: issuer,
      $oidc_subject: subject,
      $updated_at: new Date().toISOString(),
    }).changes > 0;
  }

  revokeOidcSession(issuer: string, sessionId: string, expiresAt: number): void {
    this.pruneRevokedOidcSessionsStatement.run({ $now: Math.floor(Date.now() / 1000) });
    this.insertRevokedOidcSessionStatement.run({ $issuer: issuer, $session_id: sessionId, $expires_at: expiresAt });
  }

  bumpOidcLogoutVersion(issuer: string, subject: string): void {
    this.bumpOidcLogoutVersionStatement.run({ $issuer: issuer, $subject: subject });
  }

  getOidcLogoutVersion(issuer: string, subject: string): number {
    const row = this.getOidcLogoutVersionStatement.get({ $issuer: issuer, $subject: subject }) as { version: number } | null;
    return row?.version ?? INITIAL_OIDC_LOGOUT_VERSION;
  }

  isOidcSessionRevoked(issuer: string, sessionId: string): boolean {
    return Boolean(this.getRevokedOidcSessionStatement.get({
      $issuer: issuer,
      $session_id: sessionId,
      $now: Math.floor(Date.now() / 1000),
    }));
  }

  revokeAuthSession(sessionId: string, expiresAt: number): void {
    this.pruneRevokedAuthSessionsStatement.run({ $now: Math.floor(Date.now() / 1000) });
    this.insertRevokedAuthSessionStatement.run({ $session_id: sessionId, $expires_at: expiresAt });
  }

  isAuthSessionRevoked(sessionId: string): boolean {
    return Boolean(this.getRevokedAuthSessionStatement.get({
      $session_id: sessionId,
      $now: Math.floor(Date.now() / 1000),
    }));
  }

  listWebAuthnCredentialsByUser(userId: number): WebAuthnCredentialRow[] {
    return this.listWebAuthnCredentialsByUserStatement.all({ $user_id: userId }) as WebAuthnCredentialRow[];
  }

  countWebAuthnCredentials(): number {
    return (this.countWebAuthnCredentialsStatement.get() as CountRow).count;
  }

  createWebAuthnCredential(params: {
    userId: number;
    credentialId: string;
    publicKey: string;
    signCount: number;
    transports: string | null;
    name: string | null;
  }): number {
    const result = this.createWebAuthnCredentialStatement.run({
      $user_id: params.userId,
      $credential_id: params.credentialId,
      $public_key: params.publicKey,
      $sign_count: params.signCount,
      $transports: params.transports,
      $name: params.name,
      $created_at: new Date().toISOString(),
    }) as { lastInsertRowid?: number | bigint };
    return Number(result.lastInsertRowid);
  }

  getWebAuthnCredentialByCredentialId(credentialId: string): WebAuthnCredentialRow | null {
    return (this.getWebAuthnCredentialByCredentialIdStatement.get({ $credential_id: credentialId }) as WebAuthnCredentialRow | null) || null;
  }

  updateWebAuthnCredentialCounter(id: number, signCount: number): void {
    this.updateWebAuthnCredentialCounterStatement.run({ $id: id, $sign_count: signCount });
  }

  renameWebAuthnCredential(id: number, userId: number, name: string | null): boolean {
    return this.renameWebAuthnCredentialStatement.run({ $id: id, $user_id: userId, $name: name }).changes > 0;
  }

  deleteWebAuthnCredential(id: number, userId: number): boolean {
    return this.deleteWebAuthnCredentialStatement.run({ $id: id, $user_id: userId }).changes > 0;
  }
}
