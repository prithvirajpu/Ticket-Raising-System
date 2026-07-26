import CustomerCard from "./CustomerCard";
import SummaryCard from "./SummaryCard";

const DeliveryIssueDetails = ({ data }) => {

    const {
        customer,
        delivery,
        shipping_address,
        saved_address,
        products,
        summary,
    } = data;

    return (

        <div className="border border-green-200 bg-green-50 rounded-2xl p-6 space-y-6">

            <h2 className="text-2xl font-bold text-green-700">
                Verified Delivery Details
            </h2>

            <CustomerCard customer={customer} />

            <Section title="Delivery Information">

                <Info label="Order ID" value={delivery.order_id} />
                <Info label="Delivery Status" value={delivery.delivery_status} />
                <Info label="Payment Status" value={delivery.payment_status} />
                <Info label="Payment Method" value={delivery.payment_method} />
                <Info label="Total Amount" value={`₹ ${delivery.total_amount}`} />
                <Info label="Final Amount" value={`₹ ${delivery.final_total}`} />

            </Section>

            <AddressCard
                title="Shipping Address"
                address={shipping_address}
            />

            {saved_address && (

                <AddressCard
                    title="Saved Address"
                    address={saved_address}
                />

            )}

            <div className="bg-white border rounded-xl p-5">

                <h3 className="font-semibold text-lg mb-4">
                    Products
                </h3>

                <div className="space-y-4">

                    {products.map((item,index)=>(

                        <div
                            key={index}
                            className="border rounded-lg p-4"
                        >

                            <h4 className="font-semibold">
                                {item.product.name}
                            </h4>

                            <div className="grid md:grid-cols-3 gap-4 mt-3">

                                <Info label="Status" value={item.delivery_item.status}/>
                                <Info label="Quantity" value={item.delivery_item.quantity}/>
                                <Info label="Size" value={item.delivery_item.size}/>
                                <Info label="Return Requested" value={item.delivery_item.return_requested ? "Yes":"No"}/>
                                <Info label="Cancelled" value={item.delivery_item.is_cancelled ? "Yes":"No"}/>
                                <Info label="Purchase Price" value={`₹ ${item.delivery_item.purchase_price}`}/>

                            </div>

                        </div>

                    ))}

                </div>

            </div>

            <SummaryCard summary={summary} />

        </div>

    );

};

const Section=({title,children})=>(<div className="bg-white border rounded-xl p-5"><h3 className="font-semibold text-lg mb-4">{title}</h3><div className="grid md:grid-cols-2 gap-4">{children}</div></div>);

const Info=({label,value})=>(<div><p className="text-xs uppercase text-gray-500">{label}</p><p>{value||"-"}</p></div>);

const AddressCard=({title,address})=>(<Section title={title}><Info label="Full Name" value={address.full_name}/><Info label="Email" value={address.email}/><Info label="Mobile" value={address.mobile}/><Info label="Street" value={address.street_address}/><Info label="District" value={address.district}/><Info label="State" value={address.state}/><Info label="Country" value={address.country}/><Info label="Pincode" value={address.pincode}/></Section>);

export default DeliveryIssueDetails;