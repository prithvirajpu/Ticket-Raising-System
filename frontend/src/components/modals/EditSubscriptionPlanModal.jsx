import React from "react";

const EditSubscriptionPlanModal = ({
    isOpen,
    onClose,
    editingPlan,
    onChange,
    onSubmit,
    loading,
}) => {
    if (!isOpen || !editingPlan) return null;

    return (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
            <div className="bg-white w-full max-w-3xl rounded-2xl p-6 shadow-xl max-h-[90vh] overflow-y-auto">

                {/* Header */}
                <div className="border-b border-gray-100 pb-4 mb-6">
                    <h2 className="text-lg font-bold text-gray-800">
                        Edit Subscription Plan
                    </h2>

                    <p className="text-sm text-gray-500 mt-1">
                        Update the configuration for "{editingPlan.name}".
                    </p>
                </div>

                {/* Form */}
                <form onSubmit={onSubmit} className="space-y-6">

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-5">

                        {/* Plan Name */}
                        <div>
                            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-600 mb-2">
                                Plan Name
                            </label>

                            <input
                                type="text"
                                name="name"
                                value={editingPlan.name}
                                onChange={onChange}
                                required
                                disabled={loading}
                                className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm font-medium text-gray-800 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 disabled:opacity-50"
                            />
                        </div>

                        {/* Price */}
                        <div>
                            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-600 mb-2">
                                Price ($)
                            </label>

                            <input
                                type="number"
                                name="price"
                                value={editingPlan.price}
                                onChange={onChange}
                                min="1"
                                required
                                disabled={loading}
                                className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm font-medium text-gray-800 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 disabled:opacity-50"
                            />
                        </div>

                        {/* Duration */}
                        <div>
                            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-600 mb-2">
                                Duration (Days)
                            </label>

                            <input
                                type="number"
                                name="duration_days"
                                value={editingPlan.duration_days}
                                onChange={onChange}
                                min="1"
                                required
                                disabled={loading}
                                className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm font-medium text-gray-800 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 disabled:opacity-50"
                            />
                        </div>

                        {/* Maximum Agents */}
                        <div>
                            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-600 mb-2">
                                Maximum Agents
                            </label>

                            <input
                                type="number"
                                name="max_agents"
                                value={editingPlan.max_agents}
                                onChange={onChange}
                                min="1"
                                required
                                disabled={loading}
                                className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm font-medium text-gray-800 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 disabled:opacity-50"
                            />
                        </div>

                        {/* Maximum Tickets */}
                        <div>
                            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-600 mb-2">
                                Maximum Tickets
                            </label>

                            <input
                                type="number"
                                name="max_tickets"
                                value={editingPlan.max_tickets}
                                onChange={onChange}
                                min="1"
                                required
                                disabled={loading}
                                className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm font-medium text-gray-800 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 disabled:opacity-50"
                            />
                        </div>

                    </div>

                    {/* Actions */}
                    <div className="flex justify-end gap-3 pt-4">

                        <button
                            type="button"
                            onClick={onClose}
                            disabled={loading}
                            className="px-6 py-2 text-sm font-medium text-gray-700 border border-gray-200 rounded-xl hover:bg-gray-50 transition-colors disabled:opacity-50"
                        >
                            Cancel
                        </button>

                        <button
                            type="submit"
                            disabled={loading}
                            className="px-6 py-2 text-sm font-bold text-white rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed bg-gradient-to-r from-blue-600 to-blue-700 hover:from-blue-700 hover:to-blue-800 shadow-lg hover:shadow-xl"
                        >
                            {loading ? "Saving..." : "Save Changes"}
                        </button>

                    </div>

                </form>
            </div>
        </div>
    );
};

export default EditSubscriptionPlanModal;

