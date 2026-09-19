import React, { useEffect, useState } from 'react'
import {
    getSubscriptionPlansAdmin,
    updateSubscriptionPlan
} from '../../services/ticketService'
import Loader from '../../components/modals/Loader'
import EditSubscriptionPlanModal from '../../components/modals/EditSubscriptionPlanModal'
import ConfirmModal from '../../components/modals/ConfirmModal'


const SubscriptionPlansAdmin = () => {

    const [plans, setPlans] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState('')

    const [editingPlan, setEditingPlan] = useState(null)
    const [saving, setSaving] = useState(false)

    const [confirmPlan, setConfirmPlan] = useState(null)
    const [togglingStatus, setTogglingStatus] = useState(false)


    // Fetch all plans
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


    // Open edit modal
    const handleEdit = (plan) => {

        setEditingPlan({
            id: plan.id,
            name: plan.name,
            price: plan.price,
            duration_days: plan.duration_days,
            max_agents: plan.max_agents,
            max_tickets: plan.max_tickets,
        })

    }


    // Handle input changes inside modal
    const handleEditChange = (event) => {

        const { name, value } = event.target

        setEditingPlan((previous) => ({
            ...previous,
            [name]: value
        }))

    }


    // Update plan
    const handleUpdate = async (event) => {

        event.preventDefault()

        setSaving(true)
        setError('')

        try {

            const result = await updateSubscriptionPlan(
                editingPlan.id,
                {
                    name: editingPlan.name,
                    price: Number(editingPlan.price),
                    duration_days: Number(editingPlan.duration_days),
                    max_agents: Number(editingPlan.max_agents),
                    max_tickets: Number(editingPlan.max_tickets),
                }
            )


            if (result.errors && Object.keys(result.errors).length > 0) {

                setError(result.errors.details)

                return
            }


            // Close modal
            setEditingPlan(null)


            // Refresh plans
            await fetchPlans()

        } catch (err) {

            setError(
                err.response?.data?.errors?.details ||
                'Unable to update subscription plan'
            )

        } finally {

            setSaving(false)

        }
    }
    const handleToggleStatus = (plan) => {

    setConfirmPlan(plan)
}
const handleConfirmToggleStatus = async () => {

    if (!confirmPlan) {
        return
    }

    const action = confirmPlan.is_active
        ? 'deactivate'
        : 'activate'


    setTogglingStatus(true)
    setError('')


    try {

        const result = await updateSubscriptionPlan(
            confirmPlan.id,
            {
                is_active: !confirmPlan.is_active
            }
        )


        if (result.errors && Object.keys(result.errors).length > 0) {

            setError(result.errors.details)

            return
        }


        setConfirmPlan(null)

        await fetchPlans()

    } catch (err) {

        setError(
            err.response?.data?.errors?.details ||
            `Unable to ${action} subscription plan`
        )

    } finally {

        setTogglingStatus(false)

    }
}


    return (
        <>

            {/* Header */}
            <div className="border-b border-gray-100 pb-4 mb-6 flex justify-between items-center">

                <div>

                    <h3 className="text-xl font-bold text-gray-800">
                        All Packages
                    </h3>

                    <p className="text-sm text-gray-500 mt-0.5">
                        Active and inactive tier configurations configured in the system.
                    </p>

                </div>

            </div>


            {/* Error */}
            {error && (

                <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl text-red-600 text-sm font-medium">

                    {error}

                </div>

            )}


            {/* Loading */}
            {loading ? (

                <div className="py-16 flex justify-center">

                    <Loader />

                </div>

            ) : plans.length === 0 ? (

                <div className="py-12 text-center text-gray-500 bg-white rounded-2xl border border-gray-200">

                    No subscription plans found.

                </div>

            ) : (

                /* Plans */
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">

                    {plans.map((plan) => (

                        <div
                            key={plan.id}
                            className="bg-white rounded-2xl border border-gray-200 hover:border-gray-300/90 hover:shadow-lg transition-all duration-300 p-6 flex flex-col justify-between relative overflow-hidden"
                        >

                            {/* Status */}
                            <span
                                className={`absolute top-0 right-0 text-[10px] uppercase font-bold tracking-widest px-3 py-1 rounded-bl-xl ${
                                    plan.is_active
                                        ? 'bg-green-100 text-green-800'
                                        : 'bg-gray-100 text-gray-500'
                                }`}
                            >

                                {plan.is_active ? 'Active' : 'Inactive'}

                            </span>


                            <div>

                                {/* ID */}
                                <div className="text-xs text-gray-400 font-mono mb-1">
                                    ID: #{plan.id}
                                </div>


                                {/* Plan Name */}
                                <h2 className="text-xl font-bold text-gray-800 tracking-tight mb-1">

                                    {plan.name}

                                </h2>


                                {/* Price */}
                                <div className="flex items-baseline gap-1 my-4">

                                    <span className="text-4xl font-extrabold text-gray-900 tracking-tight">

                                        ${plan.price}

                                    </span>

                                    <span className="text-gray-400 text-sm font-medium">

                                        /{plan.duration_days} Days

                                    </span>

                                </div>


                                <hr className="border-gray-100 my-4" />


                                {/* Plan Limits */}
                                <div className="space-y-3.5 text-sm text-gray-600">

                                    <div className="flex items-center gap-3">

                                        <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-50 flex items-center justify-center text-blue-600 text-xs font-bold">
                                            ✓
                                        </span>

                                        <p>
                                            <span className="font-medium text-gray-800">
                                                Duration:
                                            </span>{' '}

                                            {plan.duration_days} Days
                                        </p>

                                    </div>


                                    <div className="flex items-center gap-3">

                                        <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-50 flex items-center justify-center text-blue-600 text-xs font-bold">
                                            ✓
                                        </span>

                                        <p>
                                            <span className="font-medium text-gray-800">
                                                Max Agents:
                                            </span>{' '}

                                            {plan.max_agents}
                                        </p>

                                    </div>


                                    <div className="flex items-center gap-3">

                                        <span className="flex-shrink-0 w-5 h-5 rounded-full bg-blue-50 flex items-center justify-center text-blue-600 text-xs font-bold">
                                            ✓
                                        </span>

                                        <p>
                                            <span className="font-medium text-gray-800">
                                                Max Tickets:
                                            </span>{' '}

                                            {plan.max_tickets}
                                        </p>

                                    </div>

                                </div>


                                {/* Stripe Information */}
                                <div className="mt-6 pt-4 border-t border-gray-100 space-y-2 text-xs font-mono bg-gray-50/70 p-3 rounded-xl border">

                                    <div>

                                        <span className="text-gray-400 uppercase font-sans font-semibold block text-[10px]">
                                            Stripe Product
                                        </span>

                                        <span className="text-gray-700 break-all">
                                            {plan.stripe_product_id || 'N/A'}
                                        </span>

                                    </div>


                                    <div>

                                        <span className="text-gray-400 uppercase font-sans font-semibold block text-[10px]">
                                            Stripe Price
                                        </span>

                                        <span className="text-gray-700 break-all">
                                            {plan.stripe_price_id || 'N/A'}
                                        </span>

                                    </div>

                                </div>

                            </div>


                            {/* Edit Button */}
<div className="mt-4 flex justify-end gap-2">

    <button
        type="button"
        onClick={() => handleEdit(plan)}
        className="px-4 py-2 bg-gray-900 hover:bg-gray-800 text-white text-sm font-medium rounded-xl transition"
    >
        Edit Plan
    </button>

    <button
        type="button"
        onClick={() => handleToggleStatus(plan)}
        className={`px-4 py-2 text-sm font-medium rounded-xl transition ${
            plan.is_active
                ? "bg-red-50 text-red-600 hover:bg-red-100"
                : "bg-green-50 text-green-700 hover:bg-green-100"
        }`}
    >
        {plan.is_active ? "Deactivate" : "Activate"}
    </button>

</div>

                        </div>

                    ))}

                </div>

            )}


            {/* Edit Modal */}
            <EditSubscriptionPlanModal
                isOpen={Boolean(editingPlan)}
                onClose={() => setEditingPlan(null)}
                editingPlan={editingPlan}
                onChange={handleEditChange}
                onSubmit={handleUpdate}
                loading={saving}
            />
            <ConfirmModal
    isOpen={Boolean(confirmPlan)}
    onCancel={() => setConfirmPlan(null)}
    onConfirm={handleConfirmToggleStatus}
    title={
        confirmPlan?.is_active
            ? 'Deactivate Subscription Plan'
            : 'Activate Subscription Plan'
    }
    message={
        confirmPlan?.is_active
            ? `Are you sure you want to deactivate "${confirmPlan.name}"? Clients will no longer be able to use this plan for new subscriptions.`
            : `Are you sure you want to activate "${confirmPlan?.name}"? This plan will become available for new subscriptions.`
    }
    confirmText={
        confirmPlan?.is_active
            ? 'Deactivate'
            : 'Activate'
    }
    loading={togglingStatus}
/>
            

        </>
    )
}


export default SubscriptionPlansAdmin
