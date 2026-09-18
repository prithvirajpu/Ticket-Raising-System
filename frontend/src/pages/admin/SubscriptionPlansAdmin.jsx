import React, { useEffect, useState } from 'react'
import { getSubscriptionPlansAdmin } from '../../services/ticketService'
import Loader from '../../components/modals/Loader'

const SubscriptionPlansAdmin = () => {
    const [plans, setPlans] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState('')

    const fetchPlans = async () => {
        setLoading(true)
        setError('')
        try {
            const result = await getSubscriptionPlansAdmin()
            if (result.errors && Object.keys(result.errors).length > 0) {
                setError(result.errors.details)
                return
            }
            setPlans(result.data || [])
            console.log(result.data)
        } catch (err) {
            setError(
                err.response?.data?.errors?.details ||
                'Unable to load subscription plans'
            )
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => {
        fetchPlans()
    }, [])

    return (
        <>
            <div className="border-b border-gray-100 pb-4 mb-6 flex justify-between items-center">
                <div>
                    <h3 className="text-xl font-bold text-gray-800">All Packages</h3>
                    <p className="text-sm text-gray-500 mt-0.5">Active and inactive tier configurations configured in the system.</p>
                </div>
            </div>

            {error && (
                <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-600 text-sm font-medium">
                    {error}
                </div>
            )}

            {loading ? (
                <div className="py-16 flex justify-center"><Loader /></div>
            ) : plans.length === 0 ? (
                <div className="py-12 text-center text-gray-500 bg-white rounded-2xl border border-gray-200">
                    No subscription plans found.
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                    {plans.map((plan) => (
                        <div
                            key={plan.id}
                            className="bg-white rounded-2xl border border-gray-200 hover:border-gray-300/90 hover:shadow-lg transition-all duration-300 p-6 flex flex-col justify-between relative overflow-hidden"
                        >
                            <span className={`absolute top-0 right-0 text-[10px] uppercase font-bold tracking-widest px-3 py-1 rounded-bl-xl ${
                                plan.is_active 
                                    ? 'bg-green-100 text-green-800' 
                                    : 'bg-gray-100 text-gray-500'
                            }`}>
                                {plan.is_active ? 'Active' : 'Inactive'}
                            </span>

                            <div>
                                <div className="text-xs text-gray-400 font-mono mb-1">ID: #{plan.id}</div>
                                <h2 className="text-xl font-bold text-gray-800 tracking-tight mb-1">
                                    {plan.name}
                                </h2>
                                
                                <div className="flex items-baseline gap-1 my-4">
                                    <span className="text-4xl font-extrabold text-gray-900 tracking-tight">₹{plan.price}</span>
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

                                <div className="mt-6 pt-4 border-t border-gray-100 space-y-2 text-xs font-mono bg-gray-50/70 p-3 rounded-xl border ">
                                    <div>
                                        <span className="text-gray-400 uppercase font-sans font-semibold block text-[10px]">Stripe Product</span>
                                        <span className="text-gray-700 break-all">{plan.stripe_product_id || 'N/A'}</span>
                                    </div>
                                    <div>
                                        <span className="text-gray-400 uppercase font-sans font-semibold block text-[10px]">Stripe Price</span>
                                        <span className="text-gray-700 break-all">{plan.stripe_price_id || 'N/A'}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </>
    )
}

export default SubscriptionPlansAdmin