import { createClient } from '@supabase/supabase-js';
import WebSocket from 'ws';
import { config } from './config.js';

// supabase-js eagerly initialises a realtime client which needs a global
// WebSocket. Node < 22 has none, so polyfill it. (We don't use realtime here,
// but the client constructor requires it to exist.)
if (!globalThis.WebSocket) {
  globalThis.WebSocket = WebSocket;
}

// Service-role client. Bypasses RLS — used ONLY server-side to:
//   1. verify a user's JWT (auth.getUser)
//   2. write scan / findings / logs rows
export const supabase = createClient(config.supabaseUrl, config.supabaseServiceKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});
