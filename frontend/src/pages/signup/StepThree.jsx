const StepThree = ({ form, setForm, loading, errors, onSubmit }) => {
  return (
    <div className="space-y-6">
      <div className="text-center mb-8">
        <h2 className="text-2xl font-semibold text-[#0f172a]">Set Your Password</h2>
        <p className="text-sm text-gray-500 mt-2">Choose a strong password</p>
      </div>

      <div className="space-y-4">
        {/* Password */}
        <div>
          <label className="block text-xs font-medium text-gray-500 mb-1">Password</label>
          <input
            className={`w-full p-3 border rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 ${
              errors.password ? "border-red-500" : "border-gray-200"
            }`}
            type="password"
            value={form.password || ""}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            placeholder="At least 8 characters"
          />
          {errors.password && (
            <p className="mt-1 text-xs text-red-600">{errors.password}</p>
          )}
        </div>

        {/* Confirm Password */}
        <div>
          <label className="block text-xs font-medium text-gray-500 mb-1">
            Confirm Password
          </label>
          <input
            className={`w-full p-3 border rounded-md focus:outline-none focus:ring-1 focus:ring-blue-500 ${
              errors.confirm_password ? "border-red-500" : "border-gray-200"
            }`}
            type="password"
            value={form.confirm_password || ""}
            onChange={(e) => setForm({ ...form, confirm_password: e.target.value })}
            placeholder="Re-enter password"
          />
          {errors.confirm_password && (
            <p className="mt-1 text-xs text-red-600">{errors.confirm_password}</p>
          )}
        </div>

        <button
          onClick={onSubmit}
          disabled={loading}
          className={`w-full bg-[#0f172a] text-white py-3 rounded-md mt-6 font-medium transition-colors ${
            loading ? "opacity-60 cursor-not-allowed" : "hover:bg-slate-800"
          }`}
        >
          {loading ? "Creating Account..." : "Finish & Verify"}
        </button>
      </div>
    </div>
  );
};

export default StepThree;