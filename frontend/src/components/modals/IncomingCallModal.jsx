import React from "react";

const IncomingCallModal = ({
  isOpen,
  callerName,
  onAccept,
  onReject,
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black/50 flex justify-center items-center z-50">
      <div className="bg-white rounded-2xl p-8 w-[400px] shadow-xl">
        <h2 className="text-2xl font-bold text-center">
          Incoming Call
        </h2>

        <p className="text-center mt-4 text-gray-600">
          {callerName} is calling you
        </p>

        <div className="flex justify-center gap-4 mt-8">
          <button
            onClick={onReject}
            className="bg-red-600 text-white px-6 py-2 rounded-lg"
          >
            Reject
          </button>

          <button
            onClick={onAccept}
            className="bg-green-600 text-white px-6 py-2 rounded-lg"
          >
            Accept
          </button>
        </div>
      </div>
    </div>
  );
};

export default IncomingCallModal;