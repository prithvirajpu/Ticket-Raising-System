import { PhoneOff } from "lucide-react";

const OngoingCallModal = ({ isOpen, onEnd }) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-white p-6 rounded-2xl w-[300px] text-center shadow-xl">

        <h2 className="text-lg font-bold mb-2">Call in Progress</h2>

        <p className="text-sm text-gray-500 mb-6">
          You are now connected
        </p>

        <button
          onClick={onEnd}
          className="bg-red-500 text-white px-4 py-2 rounded-lg flex items-center gap-2 justify-center w-full"
        >
          <PhoneOff size={18} />
          End Call
        </button>

      </div>
    </div>
  );
};

export default OngoingCallModal;