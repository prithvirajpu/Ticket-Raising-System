import React, { Suspense, useEffect, useState } from "react";
import { connectStripe, createWithdrawRequest, getWalletMoney, getWalletTransactions, } from "../../services/ticketService";
import DashboardLayout from '../../layouts/DashboardLayout'
import { notifySuccess } from "../../utils/notify";
import { Wallet, DollarSign, CreditCard, ArrowUpRight, History, Calendar, FileText, ArrowDownLeft, Landmark, AlertTriangle } from "lucide-react";
import { lazy } from "react";
import Loader from '../../components/modals/Loader'
const ConfirmModal= lazy(()=>import('../../components/modals/ConfirmModal'))

const WalletPage = () => {
  const [loading, setLoading] = useState(false);
  const [isStripeConnected, setIsStripeConnected] = useState(false);
  const [amount, setAmount] = useState('')
  const [transactions, setTransactions] = useState([]);
  const [withdrawAmount, setWithdrawAmount] = useState("");
  
  // Modal State Mechanics
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalLoading, setModalLoading] = useState(false);

  useEffect(() => {
    fetchWalletMoney();
    fetchWalletTransactions();
  }, [])

  const fetchWalletMoney = async () => {
    const res = await getWalletMoney();
    console.log("wallet fetch", res);
    setAmount(res.message.balance)
    setIsStripeConnected(res.message.is_stripe_connected);
  }
  const fetchWalletTransactions = async () => {
    const res = await getWalletTransactions();
    console.log("transactions", res);
    setTransactions(res.message);
  };

  // Intercept action to trigger confirmation interface
  const handleWithdrawClick = () => {
    if (!withdrawAmount || isNaN(withdrawAmount) || parseFloat(withdrawAmount) <= 0) return;
    setIsModalOpen(true);
  };

  // Executed inside ConfirmModal after user verifies the intent
  const handleConfirmWithdraw = async () => {
    try {
      setModalLoading(true);
      await createWithdrawRequest({ amount: withdrawAmount })
      setWithdrawAmount('')
      notifySuccess('Withdraw request successfully submitted')
      await fetchWalletMoney();
    } catch (error) {
      console.error(error);
    } finally {
      setModalLoading(false);
      setIsModalOpen(false);
    }
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
    <DashboardLayout title="Financial Operations">
      <div className="text-slate-800 antialiased space-y-6">

        {/* HEADER CONTROL PANEL */}
        <div className="bg-white border border-slate-200/80 p-5 rounded-2xl shadow-sm">
          <h2 className="text-xl font-bold text-slate-900 tracking-tight">Wallet Ledger</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Manage your accumulated payouts, initialize settlement distributions, and audit ledger transactions.
          </p>
        </div>

        {/* BALANCE & WITHDRAWAL GRID CONTROLS */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          
          {/* AVAILABLE BALANCE CARD */}
          <div className="bg-white rounded-2xl border border-slate-200/80 p-6 shadow-sm flex flex-col justify-between space-y-4">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Available Balance</span>
                <div className="p-2 bg-slate-50 border border-slate-100 rounded-xl">
                  <Wallet className="w-5 h-5 text-slate-500" />
                </div>
              </div>
              <div className="mt-4 flex items-baseline text-slate-900">
                <span className="text-2xl font-medium text-slate-400 mr-1">$</span>
                <span className="text-4xl font-extrabold tracking-tight font-mono">{amount || '--'}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">Cleared context earnings ready for settlement</p>
            </div>
            
            {!isStripeConnected  && (
                <button
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 disabled:bg-slate-200 disabled:text-slate-400 rounded-xl transition-colors shadow-sm"
              onClick={handleConnectStripe}
              disabled={loading}
            >
              <CreditCard className="w-4 h-4" />
              {loading ? "Connecting..." : "Connect Stripe Account"}
            </button>

            )}
            
          </div>

          {/* WITHDRAW MONEY CONSOLE CARD */}
          <div className="md:col-span-2 bg-white rounded-2xl border border-slate-200/80 p-6 shadow-sm flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <h4 className="text-sm font-bold text-slate-900 tracking-tight">Withdraw Money</h4>
                  <p className="text-xs text-slate-400">Initialize a payout request route into your verified settlement system</p>
                </div>
                <div className="p-2 bg-slate-50 border border-slate-100 rounded-xl">
                  <Landmark className="w-5 h-5 text-slate-500" />
                </div>
              </div>

              <div className="mt-5 relative rounded-xl shadow-sm max-w-md">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-4">
                  <DollarSign className="h-4 w-4 text-slate-400" />
                </div>
                <input
                  type="number"
                  className="block w-full rounded-xl border border-slate-200 bg-slate-50/50 py-2.5 pl-9 pr-4 text-sm font-semibold text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:bg-white focus:ring-1 focus:ring-indigo-500 transition-colors outline-none font-mono"
                  placeholder="0.00"
                  value={withdrawAmount}
                  onChange={(e) => setWithdrawAmount(e.target.value)}
                />
              </div>
            </div>

            <div className="mt-5 pt-4 border-t border-slate-100 flex items-center justify-end">
              <button
                className="inline-flex items-center gap-1.5 px-5 py-2.5 text-sm font-bold text-emerald-700 bg-emerald-50 hover:bg-emerald-100/80 border border-emerald-200 rounded-xl transition-colors shadow-sm"
                onClick={handleWithdrawClick}
              >
                <ArrowUpRight className="w-4 h-4" />
                Request Withdrawal
              </button>
            </div>
          </div>

        </div>

        {/* TRANSACTION HISTORY LEDGER MATRICES */}
        <div className="bg-white rounded-2xl border border-slate-200/80 shadow-sm overflow-hidden">
          <div className="p-5 border-b border-slate-100 flex items-center gap-2">
            <History className="w-4 h-4 text-slate-400" />
            <h4 className="text-sm font-bold text-slate-900 tracking-tight">Transaction History</h4>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left">
              <thead>
                <tr className="bg-slate-50/70 border-b border-slate-200/60 text-[11px] font-bold tracking-wider text-slate-400 uppercase">
                  <th className="p-4 font-semibold w-16">Idx</th>
                  <th className="p-4 font-semibold">Type</th>
                  <th className="p-4 font-semibold">Amount</th>
                  <th className="p-4 font-semibold">Description</th>
                  <th className="p-4 font-semibold">Date</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-slate-100 font-medium text-slate-700 text-sm">
                {transactions.length > 0 ? (
                  transactions.map((item, index) => {
                    const isDeduction = item.transaction_type === "WITHDRAWAL" || item.transaction_type === "PENALTY";
                    
                    return (
                      <tr key={item.id} className="hover:bg-slate-50/40 transition-colors group">
                        {/* Index */}
                        <td className="p-4 font-mono text-xs text-slate-400">{index + 1}</td>

                        {/* Type Badge */}
                        <td className="p-4">
                          {item.transaction_type === "SALARY" && (
                            <span className="inline-flex items-center gap-1 text-xs text-emerald-700 font-bold bg-emerald-50 px-2.5 py-1 rounded-full border border-emerald-200/40">
                              <ArrowDownLeft className="w-3 h-3 text-emerald-500" /> {item.transaction_type}
                            </span>
                          )}
                          {item.transaction_type === "INCENTIVE" && (
                            <span className="inline-flex items-center gap-1 text-xs text-indigo-700 font-bold bg-indigo-50 px-2.5 py-1 rounded-full border border-indigo-200/40">
                              <ArrowDownLeft className="w-3 h-3 text-indigo-500" /> {item.transaction_type}
                            </span>
                          )}
                          {item.transaction_type === "WITHDRAWAL" && (
                            <span className="inline-flex items-center gap-1 text-xs text-rose-700 font-bold bg-rose-50 px-2.5 py-1 rounded-full border border-rose-200/40">
                              <ArrowUpRight className="w-3 h-3 text-rose-500" /> {item.transaction_type}
                            </span>
                          )}
                          {item.transaction_type === "PENALTY" && (
                            <span className="inline-flex items-center gap-1 text-xs text-red-700 font-bold bg-red-50 px-2.5 py-1 rounded-full border border-red-200/40">
                              <AlertTriangle className="w-3 h-3 text-red-500" /> {item.transaction_type}
                            </span>
                          )}
                          {item.transaction_type !== "SALARY" && item.transaction_type !== "INCENTIVE" && item.transaction_type !== "WITHDRAWAL" && item.transaction_type !== "PENALTY" && (
                            <span className="inline-flex items-center gap-1 text-xs text-slate-600 font-bold bg-slate-50 px-2.5 py-1 rounded-full border border-slate-200/40">
                              {item.transaction_type}
                            </span>
                          )}
                        </td>

                        {/* Amount */}
                        <td className={`p-4 font-bold font-mono tracking-tight ${isDeduction ? "text-rose-600" : "text-emerald-600"}`}>
                          <span>{isDeduction ? "-" : "+"}${item.amount}</span>
                        </td>

                        {/* Description */}
                        <td className="p-4 text-slate-600 font-normal">
                          <div className="flex items-center gap-1.5 max-w-xs md:max-w-md truncate">
                            <FileText className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                            <span className="truncate">{item.description}</span>
                          </div>
                        </td>

                        {/* Date */}
                        <td className="p-4 text-slate-500 font-normal text-xs">
                          <div className="flex items-center gap-1.5">
                            <Calendar className="w-3.5 h-3.5 text-slate-400" />
                            <span>{new Date(item.created_at).toLocaleDateString()}</span>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan="5" className="text-center py-12 px-4 text-slate-400 italic">
                      <div className="flex flex-col items-center justify-center gap-2">
                        <History className="w-8 h-8 text-slate-300 stroke-[1.5]" />
                        <span>No historical transactions found in this system ledger context.</span>
                      </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
      <Suspense fallback={<Loader />}>
            <ConfirmModal
        isOpen={isModalOpen}
        loading={modalLoading}
        title="Confirm Payout Action Request"
        message={`Are you sure you want to initialize a withdrawal payload balance clearance transfer containing a total value sequence value amount equal to $${withdrawAmount}?`}
        confirmText="Confirm Settlement"
        onConfirm={handleConfirmWithdraw}
        onCancel={() => setIsModalOpen(false)}
      />
      </Suspense>

    </DashboardLayout>
  );
};

export default WalletPage;