import { useState } from "react";


const ReviewModal = ({ isOpen, onClose, onSubmit, loading }) => {
  const [rating, setRating] = useState(0);
  const [review, setReview] = useState("");
  const [hoverRating, setHoverRating] = useState(0);

  if (!isOpen) return null;

  const handleStarClick = (starRating) => {
    setRating(starRating);
  };

  const handleStarHover = (starRating) => {
    setHoverRating(starRating);
  };

  const stars = [1, 2, 3, 4, 5];

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
      <div className="bg-white w-full max-w-md rounded-2xl p-6 shadow-xl">
        <h2 className="text-lg font-bold mb-6 text-gray-800">Rate Your Experience</h2>

        {/* ⭐ Standard Star Rating */}
        <div className="flex items-center gap-2 mb-6">
          <div className="flex gap-1">
            {stars.map((star) => (
              <button
                key={star}
                type="button"
                onClick={() => handleStarClick(star)}
                onMouseEnter={() => handleStarHover(star)}
                onMouseLeave={() => setHoverRating(0)}
                className="p-1 hover:scale-110 transition-all duration-200"
                disabled={loading}
              >
                <svg
                  width="24"  // ✅ Standard size
                  height="24"
                  viewBox="0 0 20 20"  // ✅ Perfect star proportions
                  fill={star <= (hoverRating || rating) ? "#FDBF11" : "#E2E8F0"}  // ✅ Pure yellow/gray
                >
                  <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z" />
                </svg>
              </button>
            ))}
          </div>
          {rating > 0 && (
            <span className="text-sm font-medium text-gray-700 ml-3">
              {rating}/5
            </span>
          )}
        </div>

        {/* Review Textarea */}
        <textarea
          placeholder="Write your feedback (optional)..."
          value={review}
          onChange={(e) => setReview(e.target.value)}
          rows={4}
          className="w-full p-3 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none"
          disabled={loading}
        />

        {/* Actions */}
        <div className="flex justify-end gap-3 pt-6">
          <button
            onClick={onClose}
            disabled={loading}
            className="px-6 py-2 text-sm font-medium text-gray-700 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors disabled:opacity-50"
          >
            Skip
          </button>
          <button
            disabled={loading || rating === 0}
            onClick={() => onSubmit({ rating: Number(rating), review })}
            className="px-6 py-2 text-sm font-bold text-white rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed
              bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 shadow-lg hover:shadow-xl"
          >
            {loading ? "Submitting..." : "Submit Review"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default ReviewModal;
