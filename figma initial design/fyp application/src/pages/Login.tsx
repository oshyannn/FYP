import { useState } from "react";
import type { Role, Page } from "../types";

interface Props {
  navigate: (page: Page, role?: Role) => void;
}

export default function Login({ navigate }: Props) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState("");

  const accounts: Record<string, { role: Role; dest: Page }> = {
    "user@safebrowse.com": { role: "user", dest: "user-dashboard" },
    "employer@safebrowse.com": { role: "employer", dest: "employer-dashboard" },
    "admin@safebrowse.com": { role: "admin", dest: "admin-dashboard" },
  };

  const handleLogin = () => {
    const acc = accounts[email.toLowerCase()];
    if (acc && password === "password") {
      navigate(acc.dest, acc.role);
    } else {
      setError("Invalid credentials. Try user@safebrowse.com / employer@safebrowse.com / admin@safebrowse.com with password 'password'.");
    }
  };

  return (
    <div className="min-h-full bg-gradient-to-br from-slate-50 to-blue-50 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 bg-[#1e3a5f] rounded-2xl mb-4 shadow-lg">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.5C16.5 22.15 20 17.25 20 12V6l-8-4z" fill="white" fillOpacity="0.9"/>
              <path d="M9 12l2 2 4-4" stroke="#1e3a5f" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-slate-900">SafeBrowse</h1>
          <p className="text-slate-500 text-sm mt-1">Welcome back</p>
        </div>

        {/* Card */}
        <div className="bg-white rounded-2xl shadow-sm border border-slate-200 p-8">
          {error && (
            <div className="mb-4 p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 text-xs">
              {error}
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Password</label>
              <div className="relative">
                <input
                  type={showPass ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleLogin()}
                  placeholder="••••••••"
                  className="w-full px-3.5 py-2.5 pr-10 border border-slate-300 rounded-lg text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10 transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 text-xs"
                >
                  {showPass ? "Hide" : "Show"}
                </button>
              </div>
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(e) => setRemember(e.target.checked)}
                  className="w-4 h-4 accent-[#1e3a5f]"
                />
                <span className="text-sm text-slate-600">Remember me</span>
              </label>
              <button
                onClick={() => navigate("forgot-password")}
                className="text-sm text-[#1e3a5f] hover:underline font-medium"
              >
                Forgot Password?
              </button>
            </div>

            <button
              onClick={handleLogin}
              className="w-full bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors shadow-sm"
            >
              Login
            </button>
          </div>

          <p className="text-center text-sm text-slate-500 mt-5">
            {"Don't have an account? "}
            <button
              onClick={() => navigate("register")}
              className="text-[#1e3a5f] font-medium hover:underline"
            >
              Create Account
            </button>
          </p>
        </div>

        {/* Demo hint */}
        <div className="mt-4 p-3 bg-blue-50 border border-blue-200 rounded-xl text-center">
          <p className="text-xs text-blue-700 font-medium">Demo Credentials</p>
          <p className="text-xs text-blue-600 mt-1">user@ · employer@ · admin@safebrowse.com</p>
          <p className="text-xs text-blue-600">Password: password</p>
        </div>

        <p className="text-center text-xs text-slate-400 mt-6">
          Real-time protection against malicious and suspicious websites.
        </p>
      </div>
    </div>
  );
}
