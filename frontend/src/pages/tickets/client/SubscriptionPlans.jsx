import React, { useEffect, useState } from 'react'
import DashboardLayout from '../../../layouts/DashboardLayout'
import { getSubscriptionPlans, createCheckoutSession, getCurrentPlan, cancelSubscription } from '../../../services/ticketService'
import { notifyError, notifySuccess } from '../../../utils/notify'
import Loader from '../../../components/modals/Loader'
import ConfirmModal from '../../../components/modals/ConfirmModal' // Adjust path if necessary

const SubscriptionPlans = () => {
    const [plans, setPlans] = useState([])
    const [loading, setLoading] = useState(true)
    const [loadingPlan, setLoadingPlan] = useState(null)
    const [currentPlan, setCurrentPlan] = useState(null)
    
    // Modal states
    const [isCancelModalOpen, setIsCancelModalOpen] = useState(false)
    const [cancelling, setCancelling] = useState(false)

    useEffect(() => {
        fetchPlans();
        fetchCurrentPlan();
    }, [])

    const fetchCurrentPlan = async () => {
        try {
            const res = await getCurrentPlan();
            setCurrentPlan(res)
        } catch (error) {
            console.log('no current data fetch')
        }
    }

    const handleCancelSubscription = async () => {
        try {
            setCancelling(true)
            const res = await cancelSubscription();
            notifySuccess(res.message || "Subscription cancelled successfully")
            await fetchCurrentPlan();
            setIsCancelModalOpen(false)
        } catch (error) {
            notifyError(error?.response?.data?.errors?.details || 'Failed to cancel subscription')
        } finally {
            setCancelling(false)
        }
    }

    const fetchPlans = async () => {
        try {
            const response = await getSubscriptionPlans()
            setPlans(response.message || [])
        } catch (error) {
            console.log(error)
        } finally {
            setLoading(false)
        }
    }

    const handlePayment = async (planId) => {
        try {
            setLoadingPlan(planId)
            const res = await createCheckoutSession(planId);
            window.location.href = res.checkout_url
        } catch (error) {
            notifyError(error?.response?.data?.errors?.details || 'Payment initialization failed')
        } finally {
            setLoadingPlan(null)
        }
    }

    return (
        <DashboardLayout 
            title="Plans & Billing" 
            subtitle="Manage your current subscription and overview available packages"
        >
            {/* Current Active Plan Section */}
            {currentPlan && (
                <div className="bg-white border border-gray-200/80 rounded-2xl shadow-sm mb-10 overflow-hidden max-w-5xl">
                    <div className="grid grid-cols-1 lg:grid-cols-3 divide-y lg:divide-y-0 lg:divide-x divide-gray-100">
                        
                        {/* Main Info Block */}
                        <div className="p-6 lg:col-span-2">
                            <div className="flex items-center gap-3 mb-4">
                                <span className={`text-xs font-semibold tracking-wide uppercase px-2.5 py-1 rounded-full ${
                                    currentPlan.cancel_at_period_end 
                                    ? 'bg-amber-50 text-amber-700 border border-amber-200' 
                                    : 'bg-green-50 text-green-700 border border-green-200'
                                }`}>
                                    {currentPlan.cancel_at_period_end ? 'Pending Cancellation' : 'Active Account'}
                                </span>
                            </div>

                            <h2 className="text-2xl font-bold text-gray-900 tracking-tight">
                                {currentPlan.plan_name}
                            </h2>

                            <div className="grid grid-cols-2 gap-y-4 gap-x-6 mt-6 pt-4 border-t border-gray-50 text-sm">
                                <div>
                                    <span className="block text-xs font-medium text-gray-400 uppercase tracking-wider">Status</span>
                                    <span className="font-semibold text-gray-700 capitalize mt-0.5 block">{currentPlan.status}</span>
                                </div>
                                <div>
                                    <span className="block text-xs font-medium text-gray-400 uppercase tracking-wider">Auto Renew</span>
                                    <span className={`font-semibold mt-0.5 block ${currentPlan.cancel_at_period_end ? 'text-red-500' : 'text-green-600'}`}>
                                        {currentPlan.cancel_at_period_end ? 'Off' : 'On'}
                                    </span>
                                </div>
                                <div>
                                    <span className="block text-xs font-medium text-gray-400 uppercase tracking-wider">Start Date</span>
                                    <span className="font-medium text-gray-600 mt-0.5 block">{currentPlan.start_date}</span>
                                </div>
                                <div>
                                    <span className="block text-xs font-medium text-gray-400 uppercase tracking-wider">End Date</span>
                                    <span className="font-medium text-gray-600 mt-0.5 block">{currentPlan.end_date}</span>
                                </div>
                            </div>
                        </div>

                        {/* Action Control Side-Panel */}
                        <div className="p-6 bg-gray-50/50 flex flex-col justify-center lg:col-span-1">
                            {!currentPlan.cancel_at_period_end ? (
                                <div className="space-y-3">
                                    <p className="text-xs text-gray-500 leading-relaxed">
                                        Want to change packages or discontinue? You can safely shut off subscription renewals below.
                                    </p>
                                    <button
                                        onClick={() => setIsCancelModalOpen(true)}
                                        className="w-full text-center text-sm font-semibold text-red-600 hover:text-white bg-white hover:bg-red-600 border border-red-200 hover:border-red-600 transition-all duration-200 py-2.5 px-4 rounded-xl shadow-sm"
                                    >
                                        Cancel Subscription
                                    </button>
                                </div>
                            ) : (
                                <div className="space-y-2.5">
                                    <div className="flex items-center gap-2 text-amber-800 text-xs font-semibold uppercase tracking-wider">
                                        <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse"></span>
                                        Cancellation Set
                                    </div>
                                    <p className="text-xs text-gray-500 leading-normal">
                                        Access remains open until final period expiration date:
                                    </p>
                                    <div className="text-xs font-mono bg-amber-50 border border-amber-200 text-amber-900 rounded-lg p-2.5 text-center">
                                        {new Date(currentPlan.cancel_scheduled_date).toLocaleString()}
                                    </div>
                                </div>
                            )}
                        </div>

                    </div>
                </div>
            )}

            {/* Available Plans Grid Header */}
            <div className="border-b border-gray-100 pb-4 mb-6">
                <h3 className="text-xl font-bold text-gray-800">Available Packages</h3>
                <p className="text-sm text-gray-500 mt-0.5">Choose a tier that scales smoothly with your operation requirements.</p>
            </div>
            
            {loading ? (
                <div className="py-16 flex justify-center"><Loader /></div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                    {plans.map((plan) => {
                        const isCurrentActive = currentPlan?.plan_name === plan.name;
                        
                        return (
                            <div
                                key={plan.id}
                                className={`bg-white rounded-2xl border transition-all duration-300 p-6 flex flex-col justify-between relative overflow-hidden ${
                                    isCurrentActive 
                                    ? 'border-blue-500 shadow-md ring-1 ring-blue-500/20' 
                                    : 'border-gray-200 hover:border-gray-300/90 hover:shadow-lg'
                                }`}
                            >
                                {isCurrentActive && (
                                    <span className="absolute top-0 right-0 bg-blue-500 text-white text-[10px] uppercase font-bold tracking-widest px-3 py-1 rounded-bl-xl">
                                        Current Plan
                                    </span>
                                )}

                                <div>
                                    <h2 className="text-xl font-bold text-gray-800 tracking-tight mb-1">
                                        {plan.name}
                                    </h2>
                                    
                                    <div className="flex items-baseline gap-1 my-4">
                                        <span className="text-4xl font-extrabold text-gray-900 tracking-tight">${plan.price}</span>
                                        <span className="text-gray-400 text-sm font-medium">/{plan.duration_days} Days</span>
                                    </div>

                                    <hr className="border-gray-100 my-4" />

                                    <div className="space-y-3.5 text-sm text-gray-600">
                                        <div className="flex items-center gap-3">
                                            <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-50 flex items-center justify-center text-blue-600 text-xs font-bold">✓</span>
                                            <p><span className="font-medium text-gray-800">Duration:</span> {plan.duration_days} Days</p>
                                        </div>

                                        <div className="flex items-center gap-3">
                                            <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-50 flex items-center justify-center text-blue-600 text-xs font-bold">✓</span>
                                            <p><span className="font-medium text-gray-800">Max Agents:</span> {plan.max_agents}</p>
                                        </div>

                                        <div className="flex items-center gap-3">
                                            <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-50 flex items-center justify-center text-blue-600 text-xs font-bold">✓</span>
                                            <p><span className="font-medium text-gray-800">Max Tickets:</span> {plan.max_tickets}</p>
                                        </div>
                                    </div>
                                </div>

                                <button
                                    onClick={() => handlePayment(plan.id)}
                                    disabled={loadingPlan === plan.id || isCurrentActive}
                                    className={`mt-6 w-full py-3 rounded-xl font-medium tracking-wide transition-all ${
                                        isCurrentActive 
                                        ? 'bg-gray-100 text-gray-400 cursor-not-allowed'
                                        : 'bg-gray-900 text-white hover:bg-gray-800 active:scale-[0.98]'
                                    }`}
                                >
                                    {loadingPlan === plan.id ? "Processing..." : isCurrentActive ? "Active Plan" : "Upgrade Plan"}
                                </button>
                            </div>
                        );
                    })}
                </div>
            )}

            {/* Cancel Subscription Confirmation Modal */}
            <ConfirmModal
                isOpen={isCancelModalOpen}
                title="Cancel Subscription?"
                message="Are you sure you want to cancel your current package? You will retain full access to your plan benefits until the end of your running billing cycle."
                confirmText="Yes, Cancel Subscription"
                cancelText="Keep Plan"
                loading={cancelling}
                onConfirm={handleCancelSubscription}
                onCancel={() => setIsCancelModalOpen(false)}
            />
        </DashboardLayout>
    )
}

export default SubscriptionPlans