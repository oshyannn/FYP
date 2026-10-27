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

declare global {
  interface Window {
    sb: {
      api(method: string, path: string, body?: unknown): Promise<ApiResult>;
      restoreSession(): Promise<Session | null>;
    };
  }
}
