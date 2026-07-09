import React, { useEffect, useState } from "react";
import DashboardLayout from "../../layouts/DashboardLayout";
import {
  getRevenueDashboard,
  downloadFinanceReport,
} from "../../services/ticketService";
import Loader from "../../components/modals/Loader";
import Pagination from "../../components/Pagination";

const AdminRevenue = () => {
  const [revenue, setRevenue] = useState(null);
  const [salaryPage, setSalaryPage] = useState(1);
  const [salaryTotalPages, setSalaryTotalPages] = useState(1);
  const [salaryNext, setSalaryNext] = useState(null);
  const [salaryPrevious, setSalaryPrevious] = useState(null);

  const [subscriptionPage, setSubscriptionPage] = useState(1);
  const [subscriptionTotalPages, setSubscriptionTotalPages] = useState(1);
  const [subscriptionNext, setSubscriptionNext] = useState(null);
  const [subscriptionPrevious, setSubscriptionPrevious] = useState(null);

  useEffect(() => {
    fetchRevenue();
  }, [salaryPage, subscriptionPage]);

  const fetchRevenue = async () => {
    const res = await getRevenueDashboard(salaryPage, subscriptionPage);

    setRevenue(res);

    const salaryPaginator = res.salary.pagination;
    setSalaryNext(salaryPaginator.next);
    setSalaryPrevious(salaryPaginator.previous);
    setSalaryTotalPages(
      Math.ceil(salaryPaginator.count / salaryPaginator.page_size),
    );

    const subscriptionPaginator = res.subscriptions.pagination;
    setSubscriptionNext(subscriptionPaginator.next);
    setSubscriptionPrevious(subscriptionPaginator.previous);
    setSubscriptionTotalPages(
      Math.ceil(subscriptionPaginator.count / subscriptionPaginator.page_size),
    );
  };

  if (!revenue) return <Loader />;

  return (
    <DashboardLayout title="Revenue Dashboard">
      <div className="flex justify-end mb-8">
        <div className="relative inline-block w-48"></div>
        <button
          onClick={() => downloadFinanceReport()}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg"
        >
          Download Renevue Report
        </button>
      </div>

      <div className="space-y-6">
        {/* SUMMARY CARDS */}

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-5">
          <div className="bg-white rounded-xl shadow border p-5">
            <p className="text-sm text-slate-500">Total Revenue</p>
            <h2 className="text-3xl font-bold mt-2">
              ${revenue.summary.revenue}
            </h2>
          </div>

          <div className="bg-white rounded-xl shadow border p-5">
            <p className="text-sm text-slate-500">Total Salary Paid</p>
            <h2 className="text-3xl font-bold mt-2">
              ${revenue.summary.salary_paid}
            </h2>
          </div>

          <div className="bg-white rounded-xl shadow border p-5">
            <p className="text-sm text-slate-500">Net Profit</p>
            <h2 className="text-3xl font-bold mt-2 text-green-600">
              ${revenue.summary.net_profit}
            </h2>
          </div>
        </div>

        {/* CLIENT REVENUE */}

        <div className="bg-white rounded-xl shadow border overflow-hidden">
          <div className="px-6 py-4 border-b">
            <h2 className="font-semibold text-lg">
              Client Subscription Revenue
            </h2>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50">
                <tr>
                  <th className="text-left p-4">Company</th>
                  <th className="text-left p-4">Plan</th>
                  <th className="text-left p-4">Revenue</th>
                  <th className="text-left p-4">Status</th>
                  <th className="text-left p-4">Expires On</th>
                </tr>
              </thead>

              <tbody>
                {revenue.subscriptions.data.length === 0 ? (
                  <tr>
                    <td
                      colSpan="4"
                      className="py-10 text-center text-slate-400"
                    >
                      No subscriptions found.
                    </td>
                  </tr>
                ) : (
                  revenue.subscriptions.data.map((item, index) => (
                    <tr key={index} className="border-t hover:bg-slate-50">
                      <td className="p-4">{item.company}</td>

                      <td className="p-4">{item.plan}</td>

                      <td className="p-4 font-semibold">${item.amount}</td>

                      <td className="p-4">
                        <span
                          className={`px-3 py-1 rounded-full text-xs font-semibold ${
                            item.status === "ACTIVE"
                              ? "bg-green-100 text-green-700"
                              : "bg-red-100 text-red-700"
                          }`}
                        >
                          {item.status}
                        </span>
                      </td>
                      <td className="p-4 font-semibold">{item.expires_on}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="p-4 bg-slate-50 border-t flex justify-end">
            <Pagination
              currentPage={subscriptionPage}
              totalPages={subscriptionTotalPages}
              onPageChange={setSubscriptionPage}
              hasNext={!!subscriptionNext}
              hasPrevious={!!subscriptionPrevious}
            />
          </div>
        </div>

        {/* SALARY TABLE */}

        <div className="bg-white rounded-xl shadow border overflow-hidden">
          <div className="px-6 py-4 border-b">
            <h2 className="font-semibold text-lg">Salary Distribution</h2>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50">
                <tr>
                  <th className="text-left p-4">Employee</th>
                  <th className="text-left p-4">Date</th>
                  <th className="text-left p-4">Role</th>
                  <th className="text-left p-4">Salary</th>
                  <th className="text-left p-4">Incentive</th>
                  <th className="text-left p-4">Total</th>
                </tr>
              </thead>

              <tbody>
                {revenue.salary.data.length === 0 ? (
                  <tr>
                    <td
                      colSpan="6"
                      className="py-10 text-center text-slate-400"
                    >
                      No salary records found.
                    </td>
                  </tr>
                ) : (
                  revenue.salary.data.map((item, index) => (
                    <tr key={index} className="border-t hover:bg-slate-50">
                      <td className="p-4">
                        {item.user_name || item.user_email}
                      </td>

                      <td className="p-4">{item.month}</td>

                      <td className="p-4">{item.role}</td>

                      <td className="p-4">${item.salary}</td>

                      <td className="p-4">${item.incentive}</td>

                      <td className="p-4 font-bold text-green-600">
                        ${item.total}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="p-4 bg-slate-50 border-t flex justify-end">
            <Pagination
              currentPage={salaryPage}
              totalPages={salaryTotalPages}
              onPageChange={setSalaryPage}
              hasNext={!!salaryNext}
              hasPrevious={!!salaryPrevious}
            />
          </div>
        </div>

        {/* SUMMARY */}

        <div className="bg-white rounded-xl shadow border p-6">
          <h2 className="text-lg font-semibold mb-4">Revenue Summary</h2>

          <div className="grid md:grid-cols-2 gap-4">
            <div className="flex justify-between border-b pb-2">
              <span>Total Revenue</span>
              <span className="font-semibold">${revenue.summary.revenue}</span>
            </div>

            <div className="flex justify-between border-b pb-2">
              <span>Total Salary Expense</span>
              <span className="font-semibold">
                ${revenue.summary.salary_paid}
              </span>
            </div>

            <div className="flex justify-between border-b pb-2">
              <span>Net Profit</span>
              <span className="font-semibold text-green-600">
                ${revenue.summary.net_profit}
              </span>
            </div>

            <div className="flex justify-between border-b pb-2">
              <span>Pending Withdrawals</span>
              <span className="font-semibold">
                {revenue.summary.pending_salary}
              </span>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default AdminRevenue;
