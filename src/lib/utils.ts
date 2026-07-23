import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// NOTE: The previous CSRF token helpers were removed — they were generated but
// never sent to or validated by any server, so they provided no protection.
// The app authenticates with Supabase bearer tokens (not cookies), so requests
// are not CSRF-able; the real backend verifies the JWT on every call.

// Escape HTML characters to prevent XSS (Stored / DOM-based)
export function escapeHtml(str: string | null | undefined): string {
  if (!str) return '';
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
    '/': '&#x2F;'
  };
  return String(str).replace(/[&<>"'/]/g, (m) => map[m]);
}

