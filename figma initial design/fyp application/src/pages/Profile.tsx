import { useState } from "react";
import type { Role } from "../types";

interface Props { role: Role | null; }

export default function Profile({ role }: Props) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(role === "admin" ? "Admin User" : role === "employer" ? "Sarah Lim" : "John Tan");
  const [editName, setEditName] = useState(name);

  const email = role === "admin" ? "admin@safebrowse.com" : role === "employer" ? "employer@safebrowse.com" : "user@safebrowse.com";
  const roleLabel = role === "admin" ? "Administrator" : role === "employer" ? "Employer" : "User";
  const initials = name.split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase();

  return (
    <div className="max-w-xl space-y-5">
      <h2 className="text-xl font-bold text-slate-900">Profile</h2>

      <div className="bg-white rounded-xl border border-slate-200 p-6">
        {/* Avatar */}
        <div className="flex items-center gap-5 mb-6">
          <div className="w-16 h-16 rounded-2xl bg-[#1e3a5f] text-white text-xl font-bold flex items-center justify-center">
            {initials}
          </div>
          <div>
            <div className="font-semibold text-slate-900 text-lg">{name}</div>
            <div className="text-slate-500 text-sm">{email}</div>
          </div>
        </div>

        {/* Details */}
        <div className="divide-y divide-slate-100 mb-5">
          {[
            { label: "Full Name", value: name },
            { label: "Email", value: email },
            { label: "Account Type", value: roleLabel },
            { label: "Email Verification", value: "Verified ✓" },
            { label: "Account Status", value: "Active" },
          ].map(row => (
            <div key={row.label} className="flex justify-between py-3 text-sm">
              <span className="text-slate-500">{row.label}</span>
              <span className="text-slate-800 font-medium">{row.value}</span>
            </div>
          ))}
        </div>

        <div className="flex gap-3">
          <button onClick={() => { setEditing(true); setEditName(name); }}
            className="bg-[#1e3a5f] text-white px-5 py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a] transition-colors">
            Edit Profile
          </button>
          <button className="border border-slate-300 text-slate-700 px-5 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50 transition-colors">
            Change Password
          </button>
        </div>
      </div>

      {/* Edit modal */}
      {editing && (
        <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl p-6 max-w-sm w-full shadow-xl">
            <h3 className="font-semibold text-slate-900 mb-4">Edit Profile</h3>
            <div className="space-y-4 mb-5">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Full Name</label>
                <input value={editName} onChange={e => setEditName(e.target.value)}
                  className="w-full px-3.5 py-2.5 border border-slate-300 rounded-lg text-sm focus:outline-none focus:border-[#1e3a5f] focus:ring-2 focus:ring-[#1e3a5f]/10" />
              </div>
            </div>
            <div className="flex gap-3">
              <button onClick={() => setEditing(false)}
                className="flex-1 border border-slate-300 text-slate-700 py-2.5 rounded-lg text-sm font-medium hover:bg-slate-50">Cancel</button>
              <button onClick={() => { setName(editName); setEditing(false); }}
                className="flex-1 bg-[#1e3a5f] text-white py-2.5 rounded-lg text-sm font-semibold hover:bg-[#162d4a]">Save</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
