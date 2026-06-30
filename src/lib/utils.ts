import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// SECURITY FIX: CSRF Token generation and validation
const CSRF_TOKEN_KEY = 'csrf_token';
const CSRF_TOKEN_EXPIRY_KEY = 'csrf_token_expiry';
const CSRF_TOKEN_LIFETIME_MS = 24 * 60 * 60 * 1000; // 24 hours

export function generateCSRFToken(): string {
  const randomBytes = new Uint8Array(32);
  crypto.getRandomValues(randomBytes);
  const token = Array.from(randomBytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
  
  // Store token and expiry in sessionStorage
  const expiry = Date.now() + CSRF_TOKEN_LIFETIME_MS;
  try {
    sessionStorage.setItem(CSRF_TOKEN_KEY, token);
    sessionStorage.setItem(CSRF_TOKEN_EXPIRY_KEY, expiry.toString());
  } catch (e) {
    console.error('Failed to store CSRF token');
  }
  
  return token;
}

export function getCSRFToken(): string {
  try {
    const token = sessionStorage.getItem(CSRF_TOKEN_KEY);
    const expiry = sessionStorage.getItem(CSRF_TOKEN_EXPIRY_KEY);
    
    if (!token || !expiry) {
      return generateCSRFToken();
    }
    
    if (Date.now() > parseInt(expiry)) {
      sessionStorage.removeItem(CSRF_TOKEN_KEY);
      sessionStorage.removeItem(CSRF_TOKEN_EXPIRY_KEY);
      return generateCSRFToken();
    }
    
    return token;
  } catch (e) {
    console.error('Failed to get CSRF token');
    return generateCSRFToken();
  }
}

export function validateCSRFToken(token: string): boolean {
  try {
    const storedToken = sessionStorage.getItem(CSRF_TOKEN_KEY);
    const expiry = sessionStorage.getItem(CSRF_TOKEN_EXPIRY_KEY);
    
    if (!storedToken || !expiry) {
      return false;
    }
    
    if (Date.now() > parseInt(expiry)) {
      return false;
    }
    
    return token === storedToken;
  } catch (e) {
    console.error('Failed to validate CSRF token');
    return false;
  }
}

// SECURITY FIX: Escape HTML characters to prevent XSS (Stored / DOM-based)
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

