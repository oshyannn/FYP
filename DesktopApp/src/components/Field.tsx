import { useState } from "react";
import type { InputHTMLAttributes } from "react";

const base =
  "w-full px-3.5 py-2.5 border rounded-lg text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 transition-colors";

function tone(error?: string) {
  return error
    ? "border-red-400 focus:border-red-500 focus:ring-red-500/10"
    : "border-slate-300 focus:border-[#1e3a5f] focus:ring-[#1e3a5f]/10";
}

interface FieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  error?: string;
}

export function Field({ label, error, id, name, ...rest }: FieldProps) {
  const fid = id ?? name ?? label;
  return (
    <div>
      <label htmlFor={fid} className="block text-sm font-medium text-slate-700 mb-1.5">
        {label}
      </label>
      <input
        id={fid}
        name={name}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? `${fid}-err` : undefined}
        className={`${base} ${tone(error)}`}
        {...rest}
      />
      {error && (
        <p id={`${fid}-err`} className="mt-1 text-xs text-red-600">
          {error}
        </p>
      )}
    </div>
  );
}

export function PasswordField({ label, error, id, name, ...rest }: FieldProps) {
  const [show, setShow] = useState(false);
  const fid = id ?? name ?? label;
  return (
    <div>
      <label htmlFor={fid} className="block text-sm font-medium text-slate-700 mb-1.5">
        {label}
      </label>
      <div className="relative">
        <input
          id={fid}
          name={name}
          type={show ? "text" : "password"}
          maxLength={128}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${fid}-err` : undefined}
          className={`${base} pr-14 ${tone(error)}`}
          {...rest}
        />
        <button
          type="button"
          onClick={() => setShow(!show)}
          aria-label={show ? "Hide password" : "Show password"}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-700 text-xs"
        >
          {show ? "Hide" : "Show"}
        </button>
      </div>
      {error && (
        <p id={`${fid}-err`} className="mt-1 text-xs text-red-600">
          {error}
        </p>
      )}
    </div>
  );
}
