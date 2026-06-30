import React, { useEffect, useState } from "react";
import DashboardLayout from "../../layouts/DashboardLayout";
import { getAdminWalletTransactions } from "../../services/ticketService";
import { useNavigate } from "react-router-dom";

import {
  Wallet,
  Mail,
  DollarSign,
  Calendar,
  ArrowDownCircle,
  ArrowUpCircle,
  History,
} from "lucide-react";

const WalletTransactionsPage = () => {
  const [transactions, setTransactions] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    fetchTransactions();
  }, []);

  const fetchTransactions = async () => {
    try {
      const res = await getAdminWalletTransactions();
      console.log(res);
      setTransactions(res.message);
    } catch (err) {
      console.log(err);
    }
  };

  return (
    <DashboardLayout title="Wallet Transactions">
      <div className="space-y-6">

        {/* Header */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-5 flex items-center justify-between">

          <div>
            <h2 className="text-xl font-bold text-slate-900">
              Wallet Transactions
            </h2>

            <p className="text-xs text-slate-500 mt-1">
              Review all wallet credits, debits and financial activity.
            </p>
          </div>

          <button
            onClick={() => navigate("/admin/wallet-requests")}
            className="px-4 py-2 rounded-xl bg-slate-900 text-white text-sm font-semibold hover:bg-slate-800 transition"
          >
            Withdrawal Requests
          </button>

        </div>

        {/* Table */}
        <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">

          <div className="overflow-x-auto">

            <table className="w-full">

              <thead>

                <tr className="bg-slate-50 border-b text-xs uppercase tracking-wider text-slate-500">

                  <th className="p-4 text-left">User</th>

                  <th className="p-4 text-left">Transaction</th>

                  <th className="p-4 text-left">Amount</th>

                  <th className="p-4 text-left">Balance After</th>

                  <th className="p-4 text-left">Description</th>

                  <th className="p-4 text-left">Date</th>

                </tr>

              </thead>

              <tbody className="divide-y divide-slate-100">

                {transactions.length ? (

                  transactions.map((item) => (

                    <tr
                      key={item.id}
                      className="hover:bg-slate-50 transition"
                    >

                      {/* User */}

                      <td className="p-4">

                        <div className="flex items-center gap-2">

                          <Mail className="w-4 h-4 text-slate-400" />

                          <div>

                            <p className="font-medium text-slate-800">
                              {item.user_email}
                            </p>

                            <p className="text-xs text-slate-500">
                              {item.user_name}
                            </p>

                          </div>

                        </div>

                      </td>

                      {/* Type */}

                      <td className="p-4">

                        {item.transaction_type === "CREDIT" ? (

                          <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs bg-emerald-50 text-emerald-700 border border-emerald-200">

                            <ArrowDownCircle className="w-3 h-3" />

                            CREDIT

                          </span>

                        ) : (

                          <span className="inline-flex items-center gap-1 px-3 py-1 rounded-full text-xs bg-rose-50 text-rose-700 border border-rose-200">

                            <ArrowUpCircle className="w-3 h-3" />

                            {item.transaction_type}

                          </span>

                        )}

                      </td>

                      {/* Amount */}

                      <td className="p-4 font-semibold">

                        ₹{item.amount}

                      </td>

                      {/* Balance */}

                      <td className="p-4">

                        ₹{item.balance}

                      </td>

                      {/* Description */}

                      <td className="p-4 text-slate-600">

                        {item.description}

                      </td>

                      {/* Date */}

                      <td className="p-4 text-xs text-slate-500">

                        <div className="flex items-center gap-2">

                          <Calendar className="w-3 h-3" />

                          {new Date(item.created_at).toLocaleString()}

                        </div>

                      </td>

                    </tr>

                  ))

                ) : (

                  <tr>

                    <td
                      colSpan={6}
                      className="py-14 text-center text-slate-400"
                    >

                      <div className="flex flex-col items-center gap-3">

                        <History className="w-10 h-10 text-slate-300" />

                        <p>No wallet transactions available.</p>

                      </div>

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

export default WalletTransactionsPage;