import { supabase } from './supabase.js';

/**
 * Express middleware: require a valid Supabase user JWT.
 * The frontend sends `Authorization: Bearer <access_token>` (the token from
 * the logged-in Supabase session). We verify it with the service client so a
 * forged token cannot start scans.
 */
export async function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }
  const token = header.slice(7).trim();
  if (!token) return res.status(401).json({ error: 'Empty bearer token' });

  try {
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data?.user) {
      return res.status(401).json({ error: 'Invalid or expired session' });
    }
    req.user = data.user;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Auth verification failed' });
  }
}
