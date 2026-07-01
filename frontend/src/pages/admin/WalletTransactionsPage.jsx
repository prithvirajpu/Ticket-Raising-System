import React, { useEffect, useState } from "react";
import DashboardLayout from "../../layouts/DashboardLayout";
import { getAdminWalletTransactions } from "../../services/ticketService";
import { useNavigate } from "react-router-dom";
import Pagination from "../../components/Pagination";

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

  // Preserved pagination state structure to seamlessly fit the dynamic data down the line
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [nextPage, setNextPage] = useState(null);
  const [previousPage, setPreviousPage] = useState(null);

  useEffect(() => {
    fetchTransactions();
  }, [currentPage]); 

  const fetchTransactions = async () => {
    try {
      const res = await getAdminWalletTransactions(currentPage);
      console.log(res);
      setTransactions(res.message);
      const paginator= res.paginator
      setNextPage(paginator.next)
      setPreviousPage(paginator.previous)
      setTotalPages(Math.ceil(paginator.count/ paginator.page_size))
      
    } catch (err) {
      console.log(err);
    }
  };

  return (
    <DashboardLayout title="Wallet Transactions">
      <div className="text-slate-800 antialiased space-y-6">

        {/* HEADER CONTROL PANEL */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 bg-white border border-slate-200/80 p-5 rounded-2xl shadow-sm">
          <div>
            <h2 className="text-xl font-bold text-slate-900 tracking-tight">Wallet Transactions</h2>
            <p className="text-xs text-slate-500 mt-0.5">Review all wallet credits, debits, and historical financial activity ledger items.</p>
          </div>

          <button
            onClick={() => navigate("/admin/wallet-requests")}
            className="inline-flex items-center gap-2 bg-slate-950 hover:bg-slate-800 text-white text-sm font-semibold py-2.5 px-4 rounded-xl shadow-xs hover:shadow active:scale-[0.99] transition-all self-stretch sm:self-auto text-center justify-center"
          >
            Withdrawal Requests
          </button>
        </div>

        {/* DATA CONTAINER MATRICES */}
        <div className="bg-white rounded-2xl border border-slate-200/80 shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="bg-slate-50/70 border-b border-slate-200/60 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
                  <th className="p-4 font-semibold w-16">Idx</th>
                  <th className="p-4 font-semibold">User Info</th>
                  <th className="p-4 font-semibold">Transaction</th>
                  <th className="p-4 font-semibold">Amount</th>
                  <th className="p-4 font-semibold">Balance After</th>
                  <th className="p-4 font-semibold">Description</th>
                  <th className="p-4 font-semibold text-right pr-6">Date Verified</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-100 font-medium text-slate-700 text-sm">
                {transactions.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="text-center py-12 px-4 text-slate-400 italic">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <History className="w-8 h-8 text-slate-300 stroke-[1.5]" />
                        <span>No wallet transactions available matching server architecture.</span>
                      </div>
                    </td>
                  </tr>
                ) : (
                  transactions.map((item, index) => {
                    // Match the precise sequential offset indexing from Agent Roster matrix
                    const pageSize = 10;
                    const serialNumber = (currentPage - 1) * pageSize + index + 1;

                    return (
                      <tr key={item.id} className="hover:bg-slate-50/40 transition-colors group">
                        <td className="p-4 font-mono text-xs text-slate-400">{serialNumber}</td>
                        
                        <td className="p-4">
                          <div className="flex items-center gap-2">
                            <Mail className="w-3.5 h-3.5 text-slate-400" />
                            <div>
                              <span className="font-bold text-slate-900 tracking-tight block">
                                {item.user_email}
                              </span>
                              {item.user_name && (
                                <span className="text-xs text-slate-400 block mt-0.5">
                                  {item.user_name}
                                </span>
                              )}
                            </div>
                          </div>
                        </td>

                        <td className="p-4">
                          {item.transaction_type === "CREDIT" ? (
                            <span className="inline-flex items-center gap-1 text-xs text-emerald-700 font-bold bg-emerald-50 px-2.5 py-1 rounded-full border border-emerald-200/40">
                              <ArrowDownCircle className="w-3 h-3 text-emerald-500" /> CREDIT
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-xs text-rose-700 font-bold bg-rose-50 px-2.5 py-1 rounded-full border border-rose-200/40">
                              <ArrowUpCircle className="w-3 h-3 text-rose-500" /> {item.transaction_type}
                            </span>
                          )}
                        </td>

                        <td className="p-4 text-slate-900 font-bold tracking-tight">
                          ₹{item.amount}
                        </td>

                        <td className="p-4 text-slate-600 font-semibold">
                          ₹{item.balance}
                        </td>

                        <td className="p-4 text-slate-600 font-medium">
                          {item.description || <span className="text-slate-400 italic text-xs">No description</span>}
                        </td>

                        <td className="p-4 text-right pr-6 text-xs text-slate-500">
                          <div className="inline-flex items-center gap-1.5 justify-end">
                            <Calendar className="w-3 h-3 text-slate-400" />
                            <span>{new Date(item.created_at).toLocaleString()}</span>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* TABLE FOOTER CONTROL PANEL (PAGINATION) */}
          <div className="p-4 bg-slate-50/50 border-t border-slate-100 flex items-center justify-end">
            <Pagination
              currentPage={currentPage}
              totalPages={totalPages}
              onPageChange={setCurrentPage}
              hasNext={!!nextPage}
              hasPrevious={!!previousPage}
            />
          </div>
        </div>

      </div>
    </DashboardLayout>
  );
};

export default WalletTransactionsPage;