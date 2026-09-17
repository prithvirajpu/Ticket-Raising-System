import React, { useEffect, useState } from "react";
import { getClientTickets } from "../../../services/ticketService";
import DashboardLayout from "../../../layouts/DashboardLayout";
import Loader from "../../../components/modals/Loader";
import Pagination from "../../../components/Pagination";

const ClientTickets = () => {
  const [tickets, setTickets] = useState([]);
  const [statistics, setStatistics] = useState({
    total: 0,
    open: 0,
    in_progress: 0,
    escalated: 0,
    resolved: 0,
    closed: 0,
    reopened: 0,
  });
  const [selectedStatus, setSelectedStatus] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [paginator, setPaginator] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchTickets = async () => {
    try {
      setLoading(true);
      setError("");
      const res = await getClientTickets(selectedStatus, currentPage);
      console.log("CLIENT TICKETS RESPONSE:", res);

      setStatistics(res.data.statistics);
      setTickets(res.data.tickets);
      setPaginator(res.paginator);
    } catch (error) {
      console.log("fetch client tickets error", error);
      setError(
        error.response?.data?.errors?.details || "Unable to load tickets",
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTickets();
  }, [selectedStatus, currentPage]);

  const handleStatusChange = (status) => {
    setSelectedStatus(status);
    setCurrentPage(1);
  };

  const getStatusLabel = (status) => {
    const labels = {
      OPEN: "Open",
      IN_PROGRESS: "In Progress",
      ESCALATED: "Escalated",
      RESOLVED: "Resolved",
      CLOSED: "Closed",
      REOPENED: "Reopened",
    };

    return labels[status] || status;
  };

  const getStatusBadgeClass = (status) => {
    switch (status) {
      case "OPEN":
        return "bg-blue-100 text-blue-700";
      case "IN_PROGRESS":
        return "bg-amber-100 text-amber-700";
      case "ESCALATED":
        return "bg-orange-100 text-orange-700";
      case "RESOLVED":
        return "bg-green-100 text-green-700";
      case "CLOSED":
        return "bg-slate-100 text-slate-700";
      case "REOPENED":
        return "bg-purple-100 text-purple-700";
      default:
        return "bg-slate-100 text-slate-700";
    }
  };

  const getPriorityLabel = (priority) => {
    const labels = {
      LOW: "Low",
      MEDIUM: "Medium",
      HIGH: "High",
    };

    return labels[priority] || priority;
  };

  const getPriorityBadgeClass = (priority) => {
    switch (priority) {
      case "HIGH":
        return "text-red-600 font-semibold";
      case "MEDIUM":
        return "text-amber-600 font-medium";
      case "LOW":
        return "text-slate-600";
      default:
        return "text-slate-600";
    }
  };

  if (loading && tickets.length === 0) return <Loader />;

  return (
    <DashboardLayout
      title="Tickets Info"
      subtitle="Overview of your organization"
    >
      <div className="space-y-6">
        {/* SUMMARY CARDS */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-7 gap-4">
          <div className="bg-white rounded-xl shadow border p-5">
            <p className="text-sm text-slate-500">Total Tickets</p>
            <h2 className="text-3xl font-bold mt-2">{statistics.total}</h2>
          </div>

          <div className="bg-white rounded-xl shadow border p-5">
            <p className="text-sm text-slate-500">Open</p>
            <h2 className="text-3xl font-bold mt-2 text-blue-600">
              {statistics.open}
            </h2>
          </div>

          <div className="bg-white rounded-xl shadow border p-5">
            <p className="text-sm text-slate-500">In Progress</p>
            <h2 className="text-3xl font-bold mt-2 text-amber-600">
              {statistics.in_progress}
            </h2>
          </div>

          <div className="bg-white rounded-xl shadow border p-5">
            <p className="text-sm text-slate-500">Escalated</p>
            <h2 className="text-3xl font-bold mt-2 text-orange-600">
              {statistics.escalated}
            </h2>
          </div>

          <div className="bg-white rounded-xl shadow border p-5">
            <p className="text-sm text-slate-500">Resolved</p>
            <h2 className="text-3xl font-bold mt-2 text-green-600">
              {statistics.resolved}
            </h2>
          </div>

          <div className="bg-white rounded-xl shadow border p-5">
            <p className="text-sm text-slate-500">Closed</p>
            <h2 className="text-3xl font-bold mt-2 text-slate-600">
              {statistics.closed}
            </h2>
          </div>

          <div className="bg-white rounded-xl shadow border p-5">
            <p className="text-sm text-slate-500">Reopened</p>
            <h2 className="text-3xl font-bold mt-2 text-purple-600">
              {statistics.reopened}
            </h2>
          </div>
        </div>

        {/* ERROR ALERT */}
        {error && (
          <div className="p-4 bg-red-50 border border-red-200 text-red-700 rounded-xl">
            {error}
          </div>
        )}

        {/* MAIN TICKET TABLE CONTAINER */}
        <div className="bg-white rounded-xl shadow border overflow-hidden">
          <div className="px-6 py-4 border-b flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <h2 className="font-semibold text-lg">Customer Tickets</h2>

            {/* STATUS FILTER DROPDOWN */}
            <select
              className="px-3 py-2 border rounded-lg bg-slate-50 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-full sm:w-48"
              value={selectedStatus}
              onChange={(e) => handleStatusChange(e.target.value)}
            >
              <option value="">All Tickets</option>
              <option value="OPEN">Open</option>
              <option value="IN_PROGRESS">In Progress</option>
              <option value="ESCALATED">Escalated</option>
              <option value="RESOLVED">Resolved</option>
              <option value="CLOSED">Closed</option>
              <option value="REOPENED">Reopened</option>
            </select>
          </div>

          {/* TABLE CONTENT */}
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50">
                <tr>
                  <th className="text-left p-4">Ticket</th>
                  <th className="text-left p-4">Customer</th>
                  <th className="text-left p-4">Subject</th>
                  <th className="text-left p-4">Issue Type</th>
                  <th className="text-left p-4">Priority</th>
                  <th className="text-left p-4">Status</th>
                  <th className="text-left p-4">Created</th>
                </tr>
              </thead>

              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="7" className="py-10 text-center text-slate-400">
                      Loading tickets...
                    </td>
                  </tr>
                ) : tickets.length === 0 ? (
                  <tr>
                    <td colSpan="7" className="py-10 text-center text-slate-400">
                      No tickets found.
                    </td>
                  </tr>
                ) : (
                  tickets.map((ticket) => (
                    <tr key={ticket.id} className="border-t hover:bg-slate-50">
                      <td className="p-4 font-semibold text-slate-700">
                        {ticket.ticket_code}
                      </td>

                      <td className="p-4">
                        <div className="font-medium">{ticket.customer_name}</div>
                        <div className="text-xs text-slate-500">
                          {ticket.customer_email}
                        </div>
                      </td>

                      <td className="p-4 text-slate-800">{ticket.subject}</td>

                      <td className="p-4 text-slate-600">
                        {ticket.issue_type}
                      </td>

                      <td className="p-4">
                        <span className={getPriorityBadgeClass(ticket.priority)}>
                          {getPriorityLabel(ticket.priority)}
                        </span>
                      </td>

                      <td className="p-4">
                        <span
                          className={`px-3 py-1 rounded-full text-xs font-semibold ${getStatusBadgeClass(
                            ticket.status
                          )}`}
                        >
                          {getStatusLabel(ticket.status)}
                        </span>
                      </td>

                      <td className="p-4 text-slate-500">
                        {new Date(ticket.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* PAGINATION FOOTER */}
          {paginator && (
            <div className="p-4 bg-slate-50 border-t flex justify-end">
              <Pagination
                currentPage={currentPage}
                totalPages={paginator.total_pages || 1}
                onPageChange={setCurrentPage}
                hasNext={paginator.has_next}
                hasPrevious={paginator.has_previous}
              />
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
};

export default ClientTickets;