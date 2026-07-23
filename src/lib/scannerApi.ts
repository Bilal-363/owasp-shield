import { supabase } from "@/integrations/supabase/client";

// Base URL of the real scanner backend (the standalone Node server).
// Local dev default; override in production with VITE_SCANNER_API_URL.
const API_BASE =
  (import.meta.env.VITE_SCANNER_API_URL as string | undefined)?.replace(/\/$/, "") ||
  "http://localhost:8787";

async function authHeaders(): Promise<Record<string, string>> {
  const { data } = await supabase.auth.getSession();
  const token = data.session?.access_token;
  if (!token) throw new Error("Not authenticated");
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

async function handle(res: Response) {
  let body: any = null;
  try {
    body = await res.json();
  } catch {
    /* ignore */
  }
  if (!res.ok) {
    throw new Error(body?.error || `Request failed (${res.status})`);
  }
  return body;
}

export const scannerApi = {
  base: API_BASE,

  async startScan(
    targetUrl: string,
    tools: string[],
    profile: "quick" | "deep" = "quick"
  ): Promise<{ scanId: string; status: string }> {
    const res = await fetch(`${API_BASE}/scan/start`, {
      method: "POST",
      headers: await authHeaders(),
      body: JSON.stringify({ targetUrl, tools, profile }),
    });
    return handle(res);
  },

  async stopScan(scanId: string): Promise<{ status: string }> {
    const res = await fetch(`${API_BASE}/scan/stop`, {
      method: "POST",
      headers: await authHeaders(),
      body: JSON.stringify({ scanId }),
    });
    return handle(res);
  },

  async getStatus(scanId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/scan/${scanId}/status`, {
      headers: await authHeaders(),
    });
    return handle(res);
  },

  async availableTools(): Promise<{ nmap: boolean; nuclei: boolean }> {
    const res = await fetch(`${API_BASE}/tools`, { headers: await authHeaders() });
    return handle(res);
  },
};
