import React from "react";
import { Link } from "react-router-dom";
import DashboardLayout from "../../layouts/DashboardLayout";

const ConnectSuccess = () => {
  return (
    <DashboardLayout>
    <div className="container py-5">
      <div className="card shadow-sm border-0">
        <div className="card-body text-center p-5">

          <div className="mb-4">
            <i
              className="bi bi-check-circle-fill text-success"
              style={{ fontSize: "4rem" }}
            ></i>
          </div>

          <h2 className="fw-bold mb-3">
            Stripe Account Connected
          </h2>

          <p className="text-muted mb-4">
            Your Stripe payout account has been successfully connected.
            Once your account verification is completed, you can receive
            withdrawals directly to your bank account.
          </p>

          <div className="d-flex justify-content-center gap-3">
            <Link
              to="/wallet"
              className="btn btn-primary"
            >
              Go to Wallet
            </Link>

            <Link
              to="/wallet"
              className="btn btn-outline-secondary"
            >
              Dashboard
            </Link>
          </div>

        </div>
      </div>
    </div>
    </DashboardLayout>
  );
};

export default ConnectSuccess;