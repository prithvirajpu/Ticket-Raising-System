// components/modals/IncomingCallModal.jsx

import React from "react";
import { Phone, PhoneOff } from "lucide-react";

const IncomingCallModal = ({
  isOpen,
  callerName = "Unknown",
  onAccept,
  onReject,
}) => {
  if (!isOpen) return null;

  return (
    /* Dark backdrop overlay to center the modal popup box */
    <div className="fixed inset-0 bg-black/60 backdrop-blur-xs z-50 flex items-center justify-center p-4">
      
      {/* Centered Modal Container */}
      <div className="w-full max-w-md bg-[#0b141a] rounded-3xl border border-zinc-800 shadow-2xl flex flex-col justify-between p-8 text-white font-sans h-[550px] animate-in fade-in zoom-in-95 duration-200">
        
        {/* Top Section: Status & Info */}
        <div className="flex flex-col items-center mt-4 text-center">
          <span className="text-xs uppercase tracking-widest text-emerald-500 font-semibold mb-2 flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
            Incoming TRS Audio Call
          </span>
          
          <h2 className="text-2xl font-medium mt-2">
            {callerName}
          </h2>
          
          <p className="text-gray-400 text-sm mt-1">
            Ringing...
          </p>
        </div>

        {/* Middle Section: Centered Avatar Display */}
        <div className="flex justify-center my-auto">
          <div className="relative flex items-center justify-center">
            {/* Pulsing Outer Rings (Faster/More intense for incoming calls) */}
            <div className="absolute inset-0 rounded-full bg-emerald-500/20 animate-ping [animation-duration:2s]" />
            <div className="absolute inset-[-15px] rounded-full bg-emerald-500/10 animate-ping [animation-duration:1.5s]" />
            
            {/* Profile Avatar Placeholder */}
            <div className="w-32 h-32 rounded-full bg-zinc-800 border-2 border-zinc-700 flex items-center justify-center shadow-2xl relative z-10">
              <span className="text-4xl font-light text-zinc-400 uppercase">
                {callerName.charAt(0)}
              </span>
            </div>
          </div>
        </div>

        {/* Bottom Section: Side-by-Side Action Controls */}
        <div className="flex justify-center gap-16 mb-4">
          {/* Decline Button */}
          <div className="flex flex-col items-center gap-2">
            <button
              onClick={onReject}
              className="w-16 h-16 bg-red-500 hover:bg-red-600 active:scale-95 transition-all text-white rounded-full flex items-center justify-center shadow-lg"
              aria-label="Decline Call"
            >
              <PhoneOff size={26} />
            </button>
            <span className="text-xs text-gray-400 font-medium">Decline</span>
          </div>

          {/* Accept Button */}
          <div className="flex flex-col items-center gap-2">
            <button
              onClick={onAccept}
              className="w-16 h-16 bg-emerald-500 hover:bg-emerald-600 active:scale-95 transition-all text-white rounded-full flex items-center justify-center shadow-lg animate-bounce [animation-duration:2.5s]"
              aria-label="Accept Call"
            >
              <Phone size={26} className="fill-current text-white" />
            </button>
            <span className="text-xs text-gray-400 font-medium">Accept</span>
          </div>
        </div>

      </div>
    </div>
  );
};
 
export default IncomingCallModal;