import React, { useEffect, useState } from "react";
import DashboardLayout from "../../layouts/DashboardLayout";
import { approveWithdrawal, getWithdrawRequests, rejectWithdrawal } from "../../services/ticketService";
import { notifySuccess } from "../../utils/notify";

const WithdrawalRequestsPage = () => {
  const [requests, setRequests] = useState([]);

  useEffect(() => {
    fetchRequests();
  }, []);

  const handleApprove=async(Id)=>{
    await approveWithdrawal(Id)
    notifySuccess('Approved successfully')
    fetchRequests()
  }
  const handleReject=async(Id)=>{
    await rejectWithdrawal(Id)
    notifySuccess('Rejected successfully')
    fetchRequests()
  }

  const fetchRequests = async () => {
    try {
      const res = await getWithdrawRequests();
      console.log('requests',res)
      setRequests(res.message);
    } catch (error) {
      console.log(error);
    }
  };

  return (
    <DashboardLayout>
      <div className="container mt-4">
        <div className="card shadow-sm">
          <div className="card-body">
            <h3>Withdrawal Requests</h3>

            <div className="table-responsive">
              <table className="table table-bordered table-hover">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Role</th>
                    <th>Amount</th>
                    <th>Status</th>
                    <th>Requested At</th>
                    <th>Action</th>
                  </tr>
                </thead>

                <tbody>
                  {requests.length > 0 ? (
                    requests.map((item, index) => (
                      <tr key={item.id}>

                        <td>{item.user_email }</td>
                        <td>{item.user_role }</td>

                        <td>${item.amount}</td>

                        <td>
                          <span
                            className={`badge ${
                              item.status === "PENDING"
                                ? "bg-warning text-dark"
                                : item.status === "APPROVED"
                                ? "bg-success"
                                : "bg-danger"
                            }`}
                          >
                            {item.status}
                          </span>
                        </td>

                        <td>
                          {new Date(
                            item.requested_at
                          ).toLocaleString()}
                        </td>

                        <td>
                          {item.status === "PENDING" && (
                            <>
                              <button onClick={()=>handleApprove(item.id)}
                                className="btn btn-success btn-sm me-2"
                              >
                                Approve
                              </button>

                              <button onClick={()=>handleReject(item.id)}
                                className="btn btn-danger btn-sm"
                              >
                                Reject
                              </button>
                            </>
                          )}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan="6" className="text-center">
                        No withdrawal requests found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default WithdrawalRequestsPage;