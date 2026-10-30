export type Portal = "user" | "staff" | "extension";

export interface User {
  id: string;
  email: string;
  full_name: string | null;
  role: "user" | "employer" | "admin";
}

export interface Session {
  user: User;
  portal: Portal;
}

export type Screen =
  | "user-login"
  | "register"
  | "verify"
  | "forgot"
  | "reset"
  | "staff-login"
  | "staff-request"
  | "staff-forgot"
  | "staff-reset"
  | "home";

/** Carries the email (and an optional message) from one auth screen to the next. */
export interface Flow {
  email: string;
  portal: "user" | "staff";
  notice?: string;
}

export interface ApiResult {
  status: number; // 0 = the server could not be reached
  data: any;
}

/** What the extension link asks for. acct = hash of the extension account's email, hint = masked email. */
export interface OpenRequest {
  page: "dashboard" | "history" | "scanner";
  acct: string | null;
  scan: string | null;
  hint: string | null;
  hasCode: boolean;
}

declare global {
  interface Window {
    sb: {
      api(method: string, path: string, body?: unknown): Promise<ApiResult>;
      restoreSession(): Promise<Session | null>;
      /** the page the browser extension asked for (safebrowse://history ...), or null */
      takePendingPage(): Promise<OpenRequest | null>;
      /** signs this app in as the extension's account (after the person confirmed); null if the code no longer works */
      acceptLink(): Promise<Session | null>;
      dropLink(): Promise<void>;
      /** a new request arrived; call takePendingPage() to read it */
      onOpenPage(cb: () => void): () => void;
    };
  }
}
