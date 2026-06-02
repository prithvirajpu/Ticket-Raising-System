// components/modals/OngoingCallModal.jsx

import { PhoneOff } from "lucide-react";

const OngoingCallModal = ({ isOpen, onEnd }) => {
  if (!isOpen) return null;

  return (
    /* - Removed the jarring entry.
      - Combined custom CSS keyframe instructions via inline styles to ensure a buttery smooth, 
        slowing-down slide directly into the top right corner.
    */
    <div 
      className="fixed top-6 right-6 z-50 pointer-events-none"
      style={{
        animation: "slideInRight 0.6s cubic-bezier(0.16, 1, 0.3, 1) forwards"
      }}
    >
      {/* Embedded keyframe animation so you don't have to fiddle with tailwind.config.js */}
      <style>{`
        @keyframes slideInRight {
          from {
            transform: translateX(120%);
            opacity: 0;
          }
          to {
            transform: translateX(0);
            opacity: 1;
          }
        }
      `}</style>
      
      {/* Floating Widget Box */}
      <div className="bg-[#0b141a] border border-zinc-800 p-5 rounded-2xl w-[280px] text-center shadow-2xl text-white pointer-events-auto">

        {/* Top Status Indicators */}
        <div className="flex items-center justify-center gap-1.5 mb-2">
          <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
          <h2 className="text-sm font-semibold tracking-wide uppercase text-emerald-500">
            Call in Progress
          </h2>
        </div>

        <p className="text-xs text-zinc-400 mb-4">
          You are now connected
        </p>

        {/* Streamlined End Call button */}
        <button
          onClick={onEnd}
          className="bg-red-500 hover:bg-red-600 active:scale-[0.98] transition-all text-white py-2.5 px-4 rounded-xl flex items-center gap-2 justify-center w-full font-medium text-sm shadow-md"
        >
          <PhoneOff size={16} />
          End Call
        </button>

      </div>
    </div>
  );
};

export default OngoingCallModal;