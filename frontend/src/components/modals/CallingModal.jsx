// components/modals/CallingModal.jsx

import { PhoneOff } from "lucide-react";

const CallingModal = ({
    isOpen,
    userName = "User",
    onCancel,
}) => {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-[#0b141a] z-50 flex flex-col justify-between p-8 text-white font-sans">
            
            {/* Top Section: Status & Info */}
            <div className="flex flex-col items-center mt-16 text-center animate-fade-in">
                <span className="text-xs uppercase tracking-widest text-emerald-500 font-semibold mb-2 flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
                    TRS Audio Call
                </span>
                
                <h2 className="text-2xl font-medium mt-2">
                    {userName}
                </h2>
                
                <p className="text-gray-400 text-sm mt-1 animate-pulse">
                    Ringing...
                </p>
            </div>

            {/* Middle Section: Centered Avatar Display */}
            <div className="flex justify-center my-auto">
                <div className="relative flex items-center justify-center">
                    {/* Pulsing Outer Rings */}
                    <div className="absolute inset-0 rounded-full bg-emerald-600/10 animate-ping [animation-duration:3s]" />
                    <div className="absolute inset-[-20px] rounded-full bg-emerald-600/5 animate-ping [animation-duration:2s]" />
                    
                    {/* Profile Avatar Placeholder */}
                    <div className="w-32 h-32 rounded-full bg-zinc-800 border-2 border-zinc-700 flex items-center justify-center shadow-2xl relative z-10">
                        <span className="text-4xl font-light text-zinc-400 uppercase">
                            {userName.charAt(0)}
                        </span>
                    </div>
                </div>
            </div>

            {/* Bottom Section: Action Controls */}
            <div className="flex flex-col items-center mb-8">
                <button
                    onClick={onCancel}
                    className="w-16 h-16 bg-red-500 hover:bg-red-600 active:scale-95 transition-all text-white rounded-full flex items-center justify-center shadow-lg transform hover:rotate-135 duration-200"
                    aria-label="End Call"
                >
                    <PhoneOff size={28} className="transform rotate-135" />
                </button>
            </div>

        </div>
    );
};

export default CallingModal;