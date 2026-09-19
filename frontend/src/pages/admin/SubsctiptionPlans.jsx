import { useState } from "react";
import { createSubscriptionPlan } from "../../services/ticketService";
import DashboardLayout from "../../layouts/DashboardLayout";
import SubscriptionPlansAdmin from "./SubscriptionPlansAdmin";

function SubscriptionPlans() {
    const [formData, setFormData] = useState({
        name: "",
        price: "",
        duration_days: "",
        max_agents: "",
        max_tickets: "",
    });

    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState("");
    const [error, setError] = useState("");

    const handleChange = (event) => {
        const { name, value } = event.target;
        setFormData((previous) => ({
            ...previous,
            [name]: value
        }));
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        setLoading(true);
        setMessage("");
        setError("");

        try {
            const result = await createSubscriptionPlan({
                name: formData.name,
                price: Number(formData.price),
                duration_days: Number(formData.duration_days),
                max_agents: Number(formData.max_agents),
                max_tickets: Number(formData.max_tickets),
            });

            if (result.errors && Object.keys(result.errors).length > 0) {
                setError(result.errors.details);
                return;
            }

            setMessage("Subscription plan created successfully.");
            setFormData({
                name: "",
                price: "",
                duration_days: "",
                max_agents: "",
                max_tickets: "",
            });

        } catch (err) {
            setError(
                err.response?.data?.errors?.details ||
                "Something went wrong while creating the plan"
            );
        } finally {
            setLoading(false);
        }
    };

    return (
        <DashboardLayout 
            title="Subscription Plans"
            subtitle="Handle and configure subscription plans for clients"
        >
            <div className="space-y-10 max-w-7xl">
                {/* Form Section */}
                <div className="bg-white border border-gray-200/80 rounded-2xl shadow-sm p-6 sm:p-8">
                    <div className="border-b border-gray-100 pb-4 mb-6">
                        <h2 className="text-xl font-bold text-gray-900 tracking-tight">
                            Create New Subscription Plan
                        </h2>
                        <p className="text-sm text-gray-500 mt-1">
                            Set pricing tiers, quotas, and limits for new client packages.
                        </p>
                    </div>

                    {message && (
                        <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-xl text-green-700 text-sm font-medium flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-green-500"></span>
                            {message}
                        </div>
                    )}

                    {error && (
                        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-600 text-sm font-medium flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-red-500"></span>
                            {error}
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="space-y-6">
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                            {/* Plan Name */}
                            <div>
                                <label className="block text-xs font-semibold uppercase tracking-wider text-gray-600 mb-2">
                                    Plan Name
                                </label>
                                <input
                                    type="text"
                                    name="name"
                                    placeholder="e.g. Enterprise Tier"
                                    value={formData.name}
                                    onChange={handleChange}
                                    // required
                                    className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm font-medium text-gray-800 placeholder-gray-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
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
                                    placeholder="e.g. 4999"
                                    value={formData.price}
                                    onChange={handleChange}
                                    // required
                                    // min="0"
                                    className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm font-medium text-gray-800 placeholder-gray-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                                />
                            </div>

                            {/* Duration Days */}
                            <div>
                                <label className="block text-xs font-semibold uppercase tracking-wider text-gray-600 mb-2">
                                    Duration (Days)
                                </label>
                                <input
                                    type="number"
                                    name="duration_days"
                                    placeholder="e.g. 30"
                                    value={formData.duration_days}
                                    onChange={handleChange}
                                    // required
                                    // min="1"
                                    className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm font-medium text-gray-800 placeholder-gray-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
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
                                    placeholder="e.g. 10"
                                    value={formData.max_agents}
                                    onChange={handleChange}
                                    // required
                                    // min="1"
                                    className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm font-medium text-gray-800 placeholder-gray-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
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
                                    placeholder="e.g. 1000"
                                    value={formData.max_tickets}
                                    onChange={handleChange}
                                    // required
                                    // min="1"
                                    className="w-full px-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm font-medium text-gray-800 placeholder-gray-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all"
                                />
                            </div>
                        </div>

                        <div className="flex justify-end pt-2">
                            <button
                                type="submit"
                                disabled={loading}
                                className="px-6 py-2.5 bg-gray-900 hover:bg-gray-800 text-white font-medium text-sm rounded-xl shadow-sm transition-all active:scale-[0.98] disabled:bg-gray-400 disabled:cursor-not-allowed"
                            >
                                {loading ? "Creating Plan..." : "Create Plan"}
                            </button>
                        </div>
                    </form>
                </div>

                {/* Existing Plans Component */}
                <SubscriptionPlansAdmin />
            </div>
        </DashboardLayout>
    );
}

export default SubscriptionPlans;