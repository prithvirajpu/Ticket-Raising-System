import CustomerCard from "./CustomerCard";
import SummaryCard from "./SummaryCard";

const WalletIssueDetails = ({ data }) => {

    const {
        customer,
        wallet,
        summary,
    } = data;

    return (

        <div className="border border-green-200 bg-green-50 rounded-2xl p-6 space-y-6">

            <h2 className="text-2xl font-bold text-green-700">
                Verified Wallet Details
            </h2>

            <CustomerCard customer={customer} />

            <div className="bg-white border rounded-xl p-5">

                <h3 className="font-semibold text-lg mb-4">
                    Wallet
                </h3>

                <div className="grid md:grid-cols-2 gap-4">

                    <Info label="Balance" value={`₹ ${wallet.balance}`} />
                    <Info label="Transactions" value={wallet.total_transactions} />
                    <Info label="Total Credit" value={`₹ ${wallet.total_credit}`} />
                    <Info label="Total Debit" value={`₹ ${wallet.total_debit}`} />

                </div>

            </div>

            {wallet.transactions?.length > 0 && (

                <div className="bg-white border rounded-xl p-5">

                    <h3 className="font-semibold text-lg mb-4">
                        Recent Transactions
                    </h3>

                    <div className="space-y-4">

                        {wallet.transactions.map((txn,index)=>(

                            <div
                                key={index}
                                className="border rounded-lg p-4"
                            >

                                <div className="grid md:grid-cols-2 gap-4">

                                    <Info label="Transaction ID" value={txn.transaction.transaction_id}/>
                                    <Info label="Type" value={txn.transaction.transaction_type}/>
                                    <Info label="Amount" value={`₹ ${txn.transaction.amount}`}/>
                                    <Info label="Description" value={txn.transaction.description}/>
                                    <Info label="Order" value={txn.linked_order?.order_id}/>
                                    <Info label="Date" value={txn.transaction.created_at}/>

                                </div>

                            </div>

                        ))}

                    </div>

                </div>

            )}

            <SummaryCard summary={summary} />

        </div>

    );

};

const Info=({label,value})=>(<div><p className="text-xs uppercase text-gray-500">{label}</p><p>{value||"-"}</p></div>);

export default WalletIssueDetails;