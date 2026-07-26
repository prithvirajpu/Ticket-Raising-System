import CustomerCard from "./CustomerCard";
import SummaryCard from "./SummaryCard";

const PaymentIssueDetails = ({ data }) => {

    const {
        customer,
        payment,
        billing,
        order,
        wallet,
        summary,
    } = data;

    return (

        <div className="border border-green-200 bg-green-50 rounded-2xl p-6 space-y-6">

            <h2 className="text-2xl font-bold text-green-700">
                Verified Payment Details
            </h2>

            <CustomerCard customer={customer} />

            <Section title="Payment Information">

                <Info label="Order ID" value={payment.order_id} />
                <Info label="Payment Method" value={payment.payment_method} />
                <Info label="Payment Status" value={payment.payment_status} />
                <Info label="Total Amount" value={`₹ ${payment.total_amount}`} />
                <Info label="Final Amount" value={`₹ ${payment.final_total}`} />
                <Info label="Created" value={payment.created_at} />

            </Section>

            <Section title="Billing Information">

                <Info label="Billing Name" value={billing.full_name} />
                <Info label="Email" value={billing.email} />
                <Info label="Phone" value={billing.mobile} />
                <Info label="Address" value={billing.street_address} />
                <Info label="District" value={billing.district} />
                <Info label="State" value={billing.state} />
                <Info label="Country" value={billing.country} />
                <Info label="Pincode" value={billing.pincode} />

            </Section>

            {wallet && (

                <Section title="Wallet">

                    <Info label="Balance" value={`₹ ${wallet.balance}`} />
                    <Info label="Transactions" value={wallet.total_transactions} />

                </Section>

            )}

            <SummaryCard summary={summary} />

        </div>

    );

};

const Section = ({ title, children }) => (
    <div className="bg-white border rounded-xl p-5">
        <h3 className="font-semibold text-lg mb-4">{title}</h3>
        <div className="grid md:grid-cols-2 gap-4">
            {children}
        </div>
    </div>
);

const Info = ({ label, value }) => (
    <div>
        <p className="text-xs uppercase text-gray-500">{label}</p>
        <p className="font-medium">{value || "-"}</p>
    </div>
);

export default PaymentIssueDetails;