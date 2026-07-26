import CustomerCard from "./CustomerCard";
import SummaryCard from "./SummaryCard";

const OrderIssueDetails = ({ data }) => {

    const {
        customer,
        order,
        shipping_address,
        saved_address,
        products,
        summary,
    } = data;

    return (

        <div className="border border-green-200 bg-green-50 rounded-2xl p-6 space-y-6">

            <h2 className="text-2xl font-bold text-green-700">
                Verified Order Details
            </h2>

            <CustomerCard customer={customer} />

            {/* Order Information */}

            <div className="bg-white border rounded-2xl p-5">

                <h3 className="text-lg font-semibold mb-4">
                    Order Information
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

                    <Info label="Order ID" value={order?.order_id} />
                    <Info label="Status" value={order?.status} />
                    <Info label="Payment Status" value={order?.payment_status} />
                    <Info label="Payment Method" value={order?.payment_method} />
                    <Info label="Total Amount" value={`₹ ${order?.total_amount}`} />
                    <Info label="Final Amount" value={`₹ ${order?.final_total}`} />
                    <Info label="Shipping Charge" value={`₹ ${order?.shipping_charge}`} />
                    <Info label="Ordered On" value={order?.created_at} />

                </div>

            </div>

            {/* Shipping Address */}

            <AddressCard
                title="Shipping Address"
                address={shipping_address}
            />

            {/* Saved Address */}

            {saved_address && (

                <AddressCard
                    title="Saved Address"
                    address={saved_address}
                />

            )}

            {/* Products */}

            <div className="bg-white border rounded-2xl p-5">

                <h3 className="text-lg font-semibold mb-5">
                    Ordered Products
                </h3>

                <div className="space-y-5">

                    {products?.map((item, index) => (

                        <div
                            key={index}
                            className="border rounded-xl p-4"
                        >

                            <h4 className="text-lg font-semibold">
                                {item.product.name}
                            </h4>

                            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mt-4">

                                <Info
                                    label="Brand"
                                    value={item.product.brand}
                                />

                                <Info
                                    label="Category"
                                    value={item.product.category}
                                />

                                <Info
                                    label="Size"
                                    value={item.order_item.size}
                                />

                                <Info
                                    label="Quantity"
                                    value={item.order_item.quantity}
                                />

                                <Info
                                    label="Purchase Price"
                                    value={`₹ ${item.order_item.purchase_price}`}
                                />

                                <Info
                                    label="Current Price"
                                    value={`₹ ${item.product.current_price}`}
                                />

                            </div>

                        </div>

                    ))}

                </div>

            </div>

            <SummaryCard summary={summary} />

        </div>

    );

};

const Info = ({ label, value }) => (

    <div>

        <p className="text-xs uppercase text-gray-500 font-bold">
            {label}
        </p>

        <p className="font-medium">
            {value || "-"}
        </p>

    </div>

);

const AddressCard = ({ title, address }) => (

    <div className="bg-white border rounded-2xl p-5">

        <h3 className="text-lg font-semibold mb-4">
            {title}
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

            <Info label="Full Name" value={address?.full_name} />
            {"email" in address && <Info label="Email" value={address?.email} />}
            <Info label="Mobile" value={address?.mobile} />
            <Info label="Street Address" value={address?.street_address} />
            <Info label="District" value={address?.district} />
            <Info label="State" value={address?.state} />
            <Info label="Country" value={address?.country} />
            <Info label="Pincode" value={address?.pincode} />

            {"is_default" in address && (
                <Info
                    label="Default"
                    value={address.is_default ? "Yes" : "No"}
                />
            )}

        </div>

    </div>

);

export default OrderIssueDetails;