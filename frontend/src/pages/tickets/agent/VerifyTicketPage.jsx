import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import DashboardLayout from "../../../layouts/DashboardLayout";
import Loader from "../../../components/modals/Loader";
import { ArrowLeft, ShieldCheck } from "lucide-react";
import { getAgentTicketDetail,verifyTicketDetails } from "../../../services/ticketService";
import { ISSUE_FIELDS } from "../../../constants/ticketConstants";

const VerifyTicketPage = () => {

    const { id } = useParams();
    const navigate = useNavigate();

    const [ticket, setTicket] = useState(null);
    const [loading, setLoading] = useState(true);

    const [verifiedData,setVerifiedData]=useState(null)
    const [formData, setFormData] = useState({email: ""});

    useEffect(() => {
        fetchTicket();
    }, []);

    const fetchTicket = async () => {
        try {
            const data = await getAgentTicketDetail(id);
            const ticketData=data.message
            setTicket(ticketData)
            setFormData({email:ticketData.customer_email || ''})
        } catch (error) {
            console.log(error);
        } finally {
            setLoading(false);
        }
    };

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleVerify = async (e) => {
        e.preventDefault();

        try {

            const payload = {
                ticket_id: id,
                issue_type: ticket.issue_type,
                ...formData
            };

            console.log('verify payload',payload);
            const response= await verifyTicketDetails(payload)
            console.log('this is verify response',response)
            setVerifiedData(response.data )

        } catch (error) {
            console.log(error);
            console.log('backend error',error.response?.data)
        }
    };

    if (loading) return <Loader />;

    const fields = ISSUE_FIELDS[ticket?.issue_type] || [];

    return (
        <DashboardLayout>

            <div className="max-w-3xl mx-auto">

                {/* Header */}

                <div className="flex items-center gap-4 mb-8">

                    <button
                        onClick={() => navigate(-1)}
                        className="hover:bg-gray-100 p-2 rounded-full"
                    >
                        <ArrowLeft size={22} />
                    </button>

                    <div>
                        <h1 className="text-2xl font-bold text-gray-900">
                            Verify Ticket
                        </h1>

                        <p className="text-sm text-gray-500">
                            Verify customer details from external platform
                        </p>
                    </div>

                </div>

                {/* Card */}

                <div className="bg-white border border-gray-200 rounded-2xl p-8 shadow-sm">

                    {/* Ticket Info */}

                    <div className="mb-8 pb-6 border-b">

                        <div className="flex items-center justify-between">

                            <div>

                                <p className="text-xs uppercase text-gray-400 font-bold">
                                    Ticket
                                </p>

                                <h2 className="text-xl font-semibold">
                                    #{ticket.ticket_code}
                                </h2>

                            </div>

                            <div className="bg-blue-100 text-blue-700 px-4 py-2 rounded-full text-xs font-bold">
                                {ticket.issue_type}
                            </div>

                        </div>

                    </div>
                    <div className="mb-8 space-y-6">

    {/* Customer Info */}

    <div className="bg-gray-50 border border-gray-200 rounded-2xl p-5">

        <h3 className="text-lg font-semibold mb-4">
            Customer Details
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

            <div>
                <p className="text-xs text-gray-400 uppercase font-bold">
                    Name
                </p>

                <p className="font-medium">
                    {ticket.customer_name}
                </p>
            </div>

            <div>
                <p className="text-xs text-gray-400 uppercase font-bold">
                    Email
                </p>

                <p className="font-medium">
                    {ticket.customer_email}
                </p>
            </div>

        </div>

    </div>

    {/* Ticket Description */}

    <div className="bg-white border border-gray-200 rounded-2xl p-5">

        <h3 className="text-lg font-semibold mb-4">
            Ticket Description
        </h3>

        <div className="space-y-3">

            <div>
                <p className="text-xs text-gray-400 uppercase font-bold mb-1">
                    Subject
                </p>

                <p className="font-medium">
                    {ticket.subject}
                </p>
            </div>

            <div>
                <p className="text-xs text-gray-400 uppercase font-bold mb-1">
                    Description
                </p>

                <div className="bg-gray-50 p-4 rounded-xl text-sm whitespace-pre-wrap">
                    {ticket.description}
                </div>
            </div>

        </div>

    </div>

</div>

                    {/* Form */}

                    <form
                        onSubmit={handleVerify}
                        className="space-y-6"
                    >

                        {fields.map((field) => (

                            <div key={field.name}>

                                <label className="block text-sm font-semibold mb-2 text-gray-700">
                                    {field.label}
                                </label>

                                <input
                                    type={field.type}
                                    name={field.name}
                                    placeholder={field.placeholder}
                                    value={formData[field.name] || ""}
                                    onChange={handleChange}
                                    className="w-full border border-gray-300 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-black"
                                />

                            </div>

                        ))}

                        {/* Submit */}

                        <div className="pt-4 flex items-center gap-4">

                            <button
                                type="submit"
                                className="bg-black text-white px-6 py-3 rounded-xl font-semibold flex items-center gap-2 hover:bg-gray-800 transition"
                            >
                                <ShieldCheck size={18} />
                                Verify Details
                            </button>

                            <button
                                type="button"
                                onClick={() => navigate(-1)}
                                className="border border-gray-300 px-6 py-3 rounded-xl font-medium hover:bg-gray-50"
                            >
                                Cancel
                            </button>

                        </div>

                    </form>
                   {verifiedData && (

    <div className="mt-8 border border-green-200 bg-green-50 rounded-2xl p-6">

        <h3 className="text-xl font-bold text-green-700 mb-6">
            Verified Details
        </h3>

        {/* ================= ORDER ISSUE ================= */}

        {verifiedData.order && (

            <div className="space-y-6">

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                    <div className="bg-white border rounded-xl p-4">
                        <p className="text-xs uppercase text-gray-500 font-bold">
                            Order ID
                        </p>

                        <p className="font-semibold">
                            {verifiedData.order.order_id}
                        </p>
                    </div>

                    <div className="bg-white border rounded-xl p-4">
                        <p className="text-xs uppercase text-gray-500 font-bold">
                            Status
                        </p>

                        <p className="font-semibold">
                            {verifiedData.order.status}
                        </p>
                    </div>

                    <div className="bg-white border rounded-xl p-4">
                        <p className="text-xs uppercase text-gray-500 font-bold">
                            Payment Status
                        </p>

                        <p className="font-semibold">
                            {verifiedData.order.payment_status}
                        </p>
                    </div>

                    <div className="bg-white border rounded-xl p-4">
                        <p className="text-xs uppercase text-gray-500 font-bold">
                            Total Amount
                        </p>

                        <p className="font-semibold">
                            ₹{verifiedData.order.total_amount}
                        </p>
                    </div>

                </div>

                {/* SHIPPING ADDRESS */}

                {verifiedData.shipping_address && (

                    <div>

                        <h4 className="font-bold mb-4">
                            Shipping Address
                        </h4>

                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                            <div className="bg-white border rounded-xl p-4">
                                <p className="text-xs uppercase text-gray-500 font-bold">
                                    Full Name
                                </p>

                                <p className="font-semibold">
                                    {verifiedData.shipping_address.full_name}
                                </p>
                            </div>

                            <div className="bg-white border rounded-xl p-4">
                                <p className="text-xs uppercase text-gray-500 font-bold">
                                    Mobile
                                </p>

                                <p className="font-semibold">
                                    {verifiedData.shipping_address.mobile}
                                </p>
                            </div>

                        </div>

                    </div>

                )}

                {/* ITEMS */}

                {verifiedData.items?.length > 0 && (

                    <div>

                        <h4 className="font-bold mb-4">
                            Order Items
                        </h4>

                        <div className="space-y-3">

                            {verifiedData.items.map((item,index)=>(

                                <div
                                    key={index}
                                    className="bg-white border rounded-xl p-4"
                                >

                                    <div className="flex justify-between">

                                        <div>

                                            <p className="font-semibold">
                                                {item.product_name}
                                            </p>

                                            <p className="text-sm text-gray-500">
                                                Size: {item.size}
                                            </p>

                                        </div>

                                        <div className="text-right">

                                            <p className="font-bold">
                                                Qty: {item.quantity}
                                            </p>

                                            <p className="text-sm text-gray-500">
                                                ₹{item.price}
                                            </p>

                                        </div>

                                    </div>

                                </div>

                            ))}

                        </div>

                    </div>

                )}

            </div>

        )}

        {/* ================= PAYMENT ISSUE ================= */}

        {verifiedData.payment_details && (

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                <div className="bg-white border rounded-xl p-4">
                    <p className="text-xs uppercase text-gray-500 font-bold">
                        Order ID
                    </p>

                    <p className="font-semibold">
                        {verifiedData.payment_details.order_id}
                    </p>
                </div>

                <div className="bg-white border rounded-xl p-4">
                    <p className="text-xs uppercase text-gray-500 font-bold">
                        Payment Method
                    </p>

                    <p className="font-semibold">
                        {verifiedData.payment_details.payment_method}
                    </p>
                </div>

                <div className="bg-white border rounded-xl p-4">
                    <p className="text-xs uppercase text-gray-500 font-bold">
                        Payment Status
                    </p>

                    <p className="font-semibold">
                        {verifiedData.payment_details.payment_status}
                    </p>
                </div>

                <div className="bg-white border rounded-xl p-4">
                    <p className="text-xs uppercase text-gray-500 font-bold">
                        Amount
                    </p>

                    <p className="font-semibold">
                        ₹{verifiedData.payment_details.total_amount}
                    </p>
                </div>

            </div>

        )}

        {/* ================= DELIVERY ISSUE ================= */}

        {verifiedData.delivery_details && (

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                <div className="bg-white border rounded-xl p-4">
                    <p className="text-xs uppercase text-gray-500 font-bold">
                        Order ID
                    </p>

                    <p className="font-semibold">
                        {verifiedData.delivery_details.order_id}
                    </p>
                </div>

                <div className="bg-white border rounded-xl p-4">
                    <p className="text-xs uppercase text-gray-500 font-bold">
                        Status
                    </p>

                    <p className="font-semibold">
                        {verifiedData.delivery_details.status}
                    </p>
                </div>

                <div className="bg-white border rounded-xl p-4">
                    <p className="text-xs uppercase text-gray-500 font-bold">
                        Customer
                    </p>

                    <p className="font-semibold">
                        {verifiedData.delivery_details.full_name}
                    </p>
                </div>

                <div className="bg-white border rounded-xl p-4">
                    <p className="text-xs uppercase text-gray-500 font-bold">
                        Mobile
                    </p>

                    <p className="font-semibold">
                        {verifiedData.delivery_details.mobile}
                    </p>
                </div>

            </div>

        )}

        {/* ================= WALLET ISSUE ================= */}

        {verifiedData.wallet && (

            <div className="space-y-6">

                <div className="bg-white border rounded-xl p-4">

                    <p className="text-xs uppercase text-gray-500 font-bold">
                        Wallet Balance
                    </p>

                    <p className="text-2xl font-bold">
                        ₹{verifiedData.wallet.balance}
                    </p>

                </div>

                {verifiedData.wallet.transactions?.length > 0 && (

                    <div>

                        <h4 className="font-bold mb-4">
                            Recent Transactions
                        </h4>

                        <div className="space-y-3">

                            {verifiedData.wallet.transactions.map((txn,index)=>(

                                <div
                                    key={index}
                                    className="bg-white border rounded-xl p-4"
                                >

                                    <div className="flex justify-between">

                                        <div>

                                            <p className="font-semibold">
                                                {txn.transaction_type}
                                            </p>

                                            <p className="text-sm text-gray-500">
                                                {txn.description}
                                            </p>

                                        </div>

                                        <div className="text-right">

                                            <p className="font-bold">
                                                ₹{txn.amount}
                                            </p>

                                            <p className="text-xs text-gray-500">
                                                {txn.transaction_id}
                                            </p>

                                        </div>

                                    </div>

                                </div>

                            ))}

                        </div>

                    </div>

                )}

            </div>

        )}

    </div>

)}
                </div>

            </div>

        </DashboardLayout>
    );
};

export default VerifyTicketPage;