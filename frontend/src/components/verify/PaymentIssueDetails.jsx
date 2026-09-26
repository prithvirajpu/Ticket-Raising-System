import CustomerCard from "./CustomerCard";
import SummaryCard from "./SummaryCard";

const PaymentIssueDetails = ({ data }) => {

    const {
        customer,
        payment,
        billing,
        shipping_address,
        wallet,
        summary,
    } = data;

    console.log("PaymentIssueDetails data:", data);
    console.log("payment:", payment);
    console.log("billing:", billing);
    console.log("shipping_address:", shipping_address);
    console.log("wallet:", wallet);
    console.log("summary:", summary);

    return (

        <div className="border border-green-200 bg-green-50 rounded-2xl p-6 space-y-6">

            <h2 className="text-2xl font-bold text-green-700">
                Verified Payment Details
            </h2>

            <CustomerCard customer={customer} />

            <Section title="Payment Information">

                <Info label="Order ID" value={payment?.order_id} />
                <Info label="Payment Method" value={payment?.payment_method} />
                <Info label="Payment Status" value={payment?.payment_status} />
                <Info label="Final Amount" value={`$ ${billing?.grand_total}`} />
                <Info label="Created" value={payment?.created_at} />

            </Section>

<Section title="Billing Information">

    <Info label="Subtotal" value={`$ ${billing?.subtotal}`} />

    <Info
        label="Coupon Code"
        value={billing?.coupon_code}
    />

    <Info
        label="Coupon Discount"
        value={`$ ${billing?.coupon_discount}`}
    />

    <Info
        label="Shipping Charge"
        value={`$ ${billing?.shipping_charge}`}
    />

    <Info
        label="Grand Total"
        value={`$ ${billing?.grand_total}`}
    />

</Section>
<Section title="Shipping Address">

    <Info
        label="Full Name"
        value={shipping_address?.full_name}
    />

    <Info
        label="Email"
        value={shipping_address?.email}
    />

    <Info
        label="Phone"
        value={shipping_address?.mobile}
    />

    <Info
        label="Address"
        value={shipping_address?.street_address}
    />

    <Info
        label="District"
        value={shipping_address?.district}
    />

    <Info
        label="State"
        value={shipping_address?.state}
    />

    <Info
        label="Country"
        value={shipping_address?.country}
    />

    <Info
        label="Pincode"
        value={shipping_address?.pincode}
    />

</Section>

            {wallet && (

                <Section title="Wallet">

                    <Info label="Balance" value={`$ ${wallet.balance}`} />
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