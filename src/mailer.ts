import { config, isProd } from './config.js';

type Log = { info: (o: object, m: string) => void };

/**
 * Stub mailer. Replace the bodies with SES/Postmark/Resend etc. In development it only logs,
 * and tokens are echoed in the API response so the flows can be exercised without email.
 */
export async function sendInvitationEmail(log: Log, to: string, token: string) {
  log.info({ to, ...(isProd ? {} : { token }) }, 'invitation email (stub mailer)');
}

/**
 * The link points at the web app, not the API: opening a URL must never change state by itself
 * (mail scanners and link previews fetch every link), so the page POSTs the token to /auth/verify-email.
 */
export async function sendVerificationEmail(log: Log, to: string, token: string) {
  const link = `${config.APP_URL}/verify-email?token=${token}`;
  log.info({ to, ...(isProd ? {} : { link }) }, 'verification email (stub mailer)');
}
