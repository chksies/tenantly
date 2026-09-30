import { isProd } from './config.js';

/**
 * Stub mailer. Replace the body with SES/Postmark/Resend etc. In development it only logs,
 * and invitation tokens are echoed in the API response so the flow can be exercised without email.
 */
export async function sendInvitationEmail(log: { info: (o: object, m: string) => void }, to: string, token: string) {
  log.info({ to, ...(isProd ? {} : { token }) }, 'invitation email (stub mailer)');
}
