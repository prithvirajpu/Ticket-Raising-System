const CustomerCard = ({ customer }) => {

    if (!customer) return null;

    return (

        <div className="bg-white border rounded-xl p-5">

            <h3 className="text-lg font-bold mb-5">
                Customer Details
            </h3>

            <div className="grid md:grid-cols-2 gap-4">

                <div>
                    <p className="text-xs uppercase text-gray-500">
                        Name
                    </p>

                    <p className="font-semibold">
                        {customer.full_name || customer.name}
                    </p>
                </div>

                <div>
                    <p className="text-xs uppercase text-gray-500">
                        Email
                    </p>

                    <p>{customer.email}</p>
                </div>

                <div>
                    <p className="text-xs uppercase text-gray-500">
                        Phone
                    </p>

                    <p>{customer.phone || customer.mobile || "-"}</p>
                </div>

                <div>
                    <p className="text-xs uppercase text-gray-500">
                        Status
                    </p>

                    <p>
                        {customer.active ? "Active" : "Inactive"}
                    </p>
                </div>

            </div>

        </div>

    );

};

export default CustomerCard;