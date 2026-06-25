import React, { useEffect, useState } from "react";
import { connectStripe, createWithdrawRequest, getWalletMoney,getWalletTransactions, } from "../../services/ticketService";
import DashboardLayout from '../../layouts/DashboardLayout'
import { notifySuccess } from "../../utils/notify";

const WalletPage = () => {
  const [loading, setLoading] = useState(false);
  const [amount,setAmount]=useState('')
  const [transactions, setTransactions] = useState([]);
  const [withdrawAmount, setWithdrawAmount] = useState("");

  useEffect(()=>{
    fetchWalletMoney();
    fetchWalletTransactions();
  },[])

    const fetchWalletMoney= async()=>{
        const res=await getWalletMoney();
        console.log('wallet money',res)
        setAmount(res.message.balance)
    }
    const fetchWalletTransactions = async () => {
        const res = await getWalletTransactions();
        console.log("transactions", res);
        setTransactions(res.message);
    };
    const handleWithdraw= async()=>{
        await createWithdrawRequest({amount: withdrawAmount})
        notifySuccess('successful withdraw request')
        setWithdrawAmount('')
    }

  const handleConnectStripe = async () => {
    try {
      setLoading(true);

      const data = await connectStripe();

      if (data?.onboarding_url) {
        window.location.href = data.onboarding_url;
      }
    } catch (error) {
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <DashboardLayout>
    <div className="container mt-4">
      <div className="card shadow-sm">
        <div className="card-body">
          <h3 className="mb-3">Wallet</h3>

          <div className="mb-4">
            <h5>Available Balance</h5>
            <h2>{amount}</h2>
          </div>

          <button
            className="btn btn-primary"
            onClick={handleConnectStripe}
            disabled={loading}
          >
            {loading ? "Connecting..." : "Connect Stripe Account"}
          </button>
        </div>
      </div>
    </div>
    <div className="mt-4">

  <h5>Withdraw Money</h5>

  <input
    type="number"
    className="form-control"
    value={withdrawAmount}
    onChange={(e) =>
      setWithdrawAmount(e.target.value)
    }
  />

  <button
    className="btn btn-success mt-2"
    onClick={handleWithdraw}
  >
    Request Withdrawal
  </button>

</div>
    <div className="card shadow-sm mt-4">
  <div className="card-body">
    <h4 className="mb-3">Transaction History</h4>

    <div className="table-responsive">
      <table className="table table-bordered table-hover">
        <thead>
          <tr>
            <th>#</th>
            <th>Type</th>
            <th>Amount</th>
            <th>Description</th>
            <th>Date</th>
          </tr>
        </thead>

        <tbody>
          {transactions.length > 0 ? (
            transactions.map((item, index) => (
              <tr key={item.id}>
                <td>{index + 1}</td>

                <td>
                  <span
                    className={`badge ${
                      item.transaction_type === "SALARY"
                        ? "bg-success"
                        : item.transaction_type === "INCENTIVE"
                        ? "bg-primary"
                        : item.transaction_type === "WITHDRAWAL"
                        ? "bg-danger"
                        : "bg-secondary"
                    }`}
                  >
                    {item.transaction_type}
                  </span>
                </td>

                <td>{item.amount}</td>

                <td>{item.description}</td>

                <td>
                  {new Date(item.created_at).toLocaleDateString()}
                </td>
              </tr>
            ))
          ) : (
            <tr>
              <td colSpan="5" className="text-center">
                No transactions found
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  </div>
</div>
    </DashboardLayout>
  );
};

export default WalletPage;