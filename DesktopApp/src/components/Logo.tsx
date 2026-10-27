export default function Logo({ staff = false }: { staff?: boolean }) {
  return (
    <div
      className={`inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-4 shadow-lg ${
        staff ? "bg-[#14284a]" : "bg-[#1e3a5f]"
      }`}
    >
      {staff ? (
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M12 3l7 3v5c0 4.5-3 8.5-7 10-4-1.5-7-5.5-7-10V6l7-3z" />
          <rect x="9" y="11" width="6" height="5" rx="1" />
          <path d="M10 11V9.5a2 2 0 0 1 4 0V11" />
        </svg>
      ) : (
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <path d="M12 2L4 6v6c0 5.25 3.5 10.15 8 11.5C16.5 22.15 20 17.25 20 12V6l-8-4z" fill="white" fillOpacity="0.9" />
          <path d="M9 12l2 2 4-4" stroke="#1e3a5f" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      )}
    </div>
  );
}
