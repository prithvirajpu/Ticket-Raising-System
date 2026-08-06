import { Loader2 } from "lucide-react";

const ConfirmModal = ({
  isOpen,
  title = "Are you sure?",
  message = "This action cannot be undone.",
  confirmText = "Confirm",    
  cancelText = "Cancel",      
  loadingText = "Processing...",  
  onConfirm,
  onCancel,
  loading = false
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 flex items-center justify-center p-4 z-[9999]">
      <div className="bg-white rounded-xl shadow-lg w-full max-w-md p-6 space-y-4 mx-4">

        <h2 className="text-lg font-semibold text-gray-800">
          {title}
        </h2>

        <p className="text-sm text-gray-600">
          {message}
        </p>

        <div className="flex justify-end gap-3 pt-4">
          <button
            onClick={onCancel}
            disabled={loading}
            className="px-4 py-2 text-sm rounded-md border border-gray-300 hover:bg-gray-100 transition"
          >
            {cancelText}
          </button>

          <button
            onClick={onConfirm}
            disabled={loading}
            className="px-4 py-2 text-sm rounded-md bg-red-600 text-white hover:bg-red-700 transition disabled:opacity-50 flex items-center gap-2 justify-center"
          >
            {loading && <Loader2 className="w-4 h-4 animate-spin" />}
            <span>{loading ? loadingText : confirmText}</span>
          </button>
        </div>

      </div>
    </div>
  );
};

export default ConfirmModal;