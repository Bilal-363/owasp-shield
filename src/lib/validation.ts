/**
 * SECURITY FIX: Client-side form validation utilities
 * Prevents invalid data from being sent to backend and provides better UX
 */

export interface ValidationResult {
  isValid: boolean;
  errors: Record<string, string>;
}

// Email validation
export const validateEmail = (email: string): boolean => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email) && email.length <= 254;
};

// URL validation
export const validateUrl = (url: string): boolean => {
  try {
    const urlObj = new URL(url);
    return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
  } catch {
    return false;
  }
};

// Password validation
export const validatePassword = (password: string): boolean => {
  return (
    password.length >= 12 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /[0-9]/.test(password) &&
    /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
  );
};

// Signup form validation
export const validateSignupForm = (email: string, password: string, fullName: string): ValidationResult => {
  const errors: Record<string, string> = {};

  if (!email || !validateEmail(email)) {
    errors.email = 'Please enter a valid email address';
  }

  if (!fullName || fullName.trim().length < 2) {
    errors.fullName = 'Full name must be at least 2 characters';
  }

  if (!validatePassword(password)) {
    errors.password = 'Password must be at least 12 characters with uppercase, lowercase, number, and special character';
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
};

// Signin form validation
export const validateSigninForm = (email: string, password: string): ValidationResult => {
  const errors: Record<string, string> = {};

  if (!email || !validateEmail(email)) {
    errors.email = 'Please enter a valid email address';
  }

  if (!password || password.length < 1) {
    errors.password = 'Password is required';
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
};

// Scan form validation
export const validateScanForm = (targetUrl: string, selectedTools: string[]): ValidationResult => {
  const errors: Record<string, string> = {};

  if (!targetUrl || !validateUrl(targetUrl)) {
    errors.targetUrl = 'Please enter a valid public URL (http or https)';
  }

  if (!selectedTools || selectedTools.length === 0) {
    errors.tools = 'Please select at least one security tool';
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
};

// Generic form field validation
export const validateField = (
  fieldName: string,
  value: any,
  type: 'email' | 'url' | 'password' | 'text' | 'number',
  options?: {
    required?: boolean;
    minLength?: number;
    maxLength?: number;
    pattern?: RegExp;
    customValidator?: (value: any) => boolean;
  }
): string | null => {
  const opts = options || {};

  if (opts.required && (!value || (typeof value === 'string' && !value.trim()))) {
    return `${fieldName} is required`;
  }

  if (!value) return null;

  if (opts.minLength && value.toString().length < opts.minLength) {
    return `${fieldName} must be at least ${opts.minLength} characters`;
  }

  if (opts.maxLength && value.toString().length > opts.maxLength) {
    return `${fieldName} must not exceed ${opts.maxLength} characters`;
  }

  if (opts.pattern && !opts.pattern.test(value)) {
    return `${fieldName} format is invalid`;
  }

  if (opts.customValidator && !opts.customValidator(value)) {
    return `${fieldName} validation failed`;
  }

  if (type === 'email' && !validateEmail(value)) {
    return 'Please enter a valid email address';
  }

  if (type === 'url' && !validateUrl(value)) {
    return 'Please enter a valid URL';
  }

  if (type === 'password' && value.length < 8) {
    return 'Password must be at least 8 characters';
  }

  if (type === 'number' && isNaN(Number(value))) {
    return `${fieldName} must be a valid number`;
  }

  return null;
};
