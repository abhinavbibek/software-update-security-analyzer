// frontend/src/components/Header.jsx
import React from "react";

export default function Header({ subtitle }) {
  return (
    <header className="w-full">
      <div className="flex flex-col items-center gap-3 text-center">
        {/* Logo + Title */}
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-indigo-500 to-indigo-300 flex items-center justify-center shadow-md">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <rect x="2" y="2" width="20" height="20" rx="4" fill="#0b1020" />
              <path
                d="M6 12h12M12 6v12"
                stroke="#0b1220"
                strokeWidth="2"
                strokeLinecap="round"
              />
            </svg>
          </div>

          <div className="text-left">
            <h1 className="text-3xl font-extrabold text-indigo-300 tracking-wide">
              VersionDiff Sentinel
            </h1>
            {subtitle && (
              <p className="text-gray-400 text-sm mt-1">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        <div className="w-full border-t border-[#0f2236] mt-2" />
      </div>
    </header>
  );
}
