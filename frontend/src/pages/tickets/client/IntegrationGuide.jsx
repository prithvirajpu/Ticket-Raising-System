import React from "react";
import DashboardLayout from "../../../layouts/DashboardLayout";

const IntegrationGuide = () => {
  return (
    <DashboardLayout
      title="Guideline"
      subtitle="Overview of your Integration Guide"
    >
      <div className="min-h-screen bg-slate-50/50 text-slate-800 antialiased">
        <div className="max-w-7xl mx-auto flex gap-8 px-4 sm:px-6 lg:px-8">
          
          {/* Sidebar Navigation */}
          <aside className="w-64 hidden lg:block shrink-0 py-8 sticky top-16 h-[calc(100vh-4rem)] overflow-y-auto hidden-scrollbar">
            <nav className="space-y-1">
              <p className="px-3 text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Documentation
              </p>
              {[
                { hash: "#overview", label: "Overview" },
                { hash: "#endpoint", label: "Endpoint Configuration" },
                { hash: "#auth", label: "Authentication" },
                { hash: "#request", label: "Request Payload" },
                { hash: "#mapping", label: "Issue Mapping" },
                { hash: "#response", label: "Response Format" },
                { hash: "#sla", label: "SLA Rules" },
                { hash: "#workflow", label: "Workflow" },
              ].map((item) => (
                <a
                  key={item.hash}
                  href={item.hash}
                  className="flex items-center px-3 py-2 text-sm font-medium text-slate-600 rounded-lg hover:bg-slate-100 hover:text-slate-900 transition-colors duration-150"
                >
                  {item.label}
                </a>
              ))}
            </nav>
          </aside>

          {/* Main Content Area */}
          <main className="flex-1 min-w-0 py-8 max-w-4xl">
            
            {/* Overview Section */}
            <section id="overview" className="scroll-mt-20 mb-12">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-4 pb-2 border-b border-slate-200">
                Overview
              </h2>
              <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-sm space-y-4">
                <p className="text-slate-600 leading-relaxed">
                  When a customer raises a support ticket, TRS agents may request
                  customer-related information from your application.
                </p>
                <p className="text-slate-600 leading-relaxed">
                  To support this functionality, your application must expose a
                  verification endpoint that receives customer and issue details
                  and returns the requested information.
                </p>
              </div>
            </section>

            {/* Endpoint Configuration Section */}
            <section id="endpoint" className="scroll-mt-20 mb-12">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-4 pb-2 border-b border-slate-200">
                Endpoint Configuration
              </h2>
              <div className="bg-slate-900 rounded-xl p-4 font-mono text-sm shadow-md flex items-center gap-3 border border-slate-800">
                <span className="bg-emerald-500/10 text-emerald-400 px-2 py-1 rounded text-xs font-bold tracking-wide">
                  POST
                </span>
                <span className="text-slate-200">/api/support/verify/</span>
              </div>
            </section>

            {/* Authentication Section */}
            <section id="auth" className="scroll-mt-20 mb-12">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-4 pb-2 border-b border-slate-200">
                Authentication
              </h2>
              <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm">
                <p className="text-slate-600 mb-4 leading-relaxed">
                  Every request from TRS will include authentication credentials.
                </p>
                <div className="bg-slate-900 text-slate-200 p-4 rounded-lg font-mono text-sm border border-slate-800">
                  <span className="text-violet-400">Authorization:</span> Bearer YOUR_SECRET_TOKEN
                </div>
              </div>
            </section>

            {/* Request Payload Section */}
            <section id="request" className="scroll-mt-20 mb-12">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-4 pb-2 border-b border-slate-200">
                Request Payload
              </h2>
              <div className="bg-slate-900 text-slate-200 rounded-xl p-5 font-mono text-sm shadow-md overflow-x-auto border border-slate-800 leading-relaxed">
                <pre>{`{
  "ticket_id": 101,
  "customer_id": 5001,
  "customer_email": user@gmail.com,
  "issue_type": "DELIVERY_ISSUE",
  "reference_id": "ORD-12345",
  "requested_by": "agent",
  "requested_at": "2026-06-08T10:30:00Z"
}`}</pre>
              </div>
            </section>

            {/* Request Fields Section */}
            <section className="scroll-mt-20 mb-12">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-4 pb-2 border-b border-slate-200">
                Request Fields
              </h2>
              <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left border-collapse">
                    <thead>
                      <tr className="bg-slate-50 border-b border-slate-200 text-slate-700 font-semibold">
                        <th className="p-4 w-1/3">Field</th>
                        <th className="p-4 w-2/3">Description</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-150 text-slate-600">
                      <tr>
                        <td className="p-4 font-mono text-indigo-600 font-semibold bg-slate-50/30">ticket_id</td>
                        <td className="p-4">TRS Ticket Identifier</td>
                      </tr>
                      <tr>
                        <td className="p-4 font-mono text-indigo-600 font-semibold bg-slate-50/30">customer_id</td>
                        <td className="p-4">Customer Identifier</td>
                      </tr>
                      <tr>
                        <td className="p-4 font-mono text-indigo-600 font-semibold bg-slate-50/30">customer_email</td>
                        <td className="p-4">Customer Email</td>
                      </tr>
                      <tr>
                        <td className="p-4 font-mono text-indigo-600 font-semibold bg-slate-50/30">issue_type</td>
                        <td className="p-4">Issue Category</td>
                      </tr>
                      <tr>
                        <td className="p-4 font-mono text-indigo-600 font-semibold bg-slate-50/30">reference_id</td>
                        <td className="p-4">Order / Refund / Payment ID</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </section>

            {/* Issue Type Mapping Section */}
            <section id="mapping" className="scroll-mt-20 mb-12">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-4 pb-2 border-b border-slate-200">
                Issue Type Mapping
              </h2>
              <div className="bg-slate-900 text-slate-200 rounded-xl p-5 font-mono text-sm shadow-md overflow-x-auto border border-slate-800 leading-relaxed">
                <pre>{`ISSUE_HANDLERS = {
  "ORDER_STATUS": get_order_status,
  "PAYMENT": get_payment_details,
  "REFUND": get_refund_status,
  "ACCOUNT": get_account_information,
  "SUBSCRIPTION": get_subscription_information
}`}</pre>
              </div>
            </section>

            {/* Responses Section */}
            <section id="response" className="scroll-mt-20 mb-12">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-4 pb-2 border-b border-slate-200">
                Success Response
              </h2>
              <div className="bg-slate-900 text-slate-200 rounded-xl p-5 font-mono text-sm shadow-md overflow-x-auto border border-slate-800 mb-8 leading-relaxed">
                <pre>{`{
  "success": true,
  "message": "Information retrieved successfully",
  "data": {
      "status": "Delivered",
      "delivery_date": "2026-06-05"
  }
}`}</pre>
              </div>

              <h2 className="text-xl font-bold tracking-tight text-slate-900 mb-4">
                Error Response
              </h2>
              <div className="bg-slate-900 text-slate-200 rounded-xl p-5 font-mono text-sm shadow-md overflow-x-auto border border-slate-800 leading-relaxed">
                <pre>{`{
  "success": false,
  "message": "Customer not found",
  "data": null
}`}</pre>
              </div>
            </section>

            {/* SLA Rules Section */}
            <section id="sla" className="scroll-mt-20 mb-12">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-4 pb-2 border-b border-slate-200">
                SLA Rules
              </h2>
              <div className="bg-white border border-slate-200 rounded-xl overflow-hidden shadow-sm mb-4">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left border-collapse">
                    <thead>
                      <tr className="bg-blue-50/70 border-b border-slate-200 text-slate-700 font-semibold">
                        <th className="p-4">Plan</th>
                        <th className="p-4">Priority</th>
                        <th className="p-4">Resolution Time</th>
                        <th className="p-4">Auto Assign</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-150 text-slate-600">
                      <tr className="hover:bg-slate-50/50 transition-colors">
                        <td className="p-4 font-semibold text-slate-900">Basic Plan</td>
                        <td className="p-4"><span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-800">LOW</span></td>
                        <td className="p-4">4320 mins (72 Hours)</td>
                        <td className="p-4 text-slate-400">Disabled</td>
                      </tr>
                      <tr className="hover:bg-slate-50/50 transition-colors">
                        <td className="p-4 font-semibold text-slate-900">Professional Plan</td>
                        <td className="p-4"><span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-800">MEDIUM</span></td>
                        <td className="p-4">2880 mins (48 Hours)</td>
                        <td className="p-4 text-emerald-600 font-medium">Enabled</td>
                      </tr>
                      <tr className="hover:bg-slate-50/50 transition-colors">
                        <td className="p-4 font-semibold text-slate-900">Enterprise Plan</td>
                        <td className="p-4"><span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-100 text-amber-800">MEDIUM</span></td>
                        <td className="p-4">1200 mins (20 Hours)</td>
                        <td className="p-4 text-emerald-600 font-medium">Enabled</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="rounded-xl border border-blue-100 bg-blue-50/60 p-4 shadow-sm backdrop-blur-sm">
                <div className="flex gap-3">
                  <span className="text-blue-600 font-bold text-sm">i</span>
                  <p className="text-sm text-slate-600 leading-relaxed">
                    <strong className="text-blue-900 font-semibold">Note:</strong> The selected subscription plan determines how
                    tickets are prioritized, the expected resolution time, and whether
                    tickets are automatically assigned to available agents. Higher-tier plans
                    receive faster resolution targets and automated assignment features.
                  </p>
                </div>
              </div>
            </section>

            {/* Verification Workflow Section */}
            <section id="workflow" className="scroll-mt-20">
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-4 pb-2 border-b border-slate-200">
                Verification Workflow
              </h2>
              <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-sm overflow-x-auto">
                <pre className="text-slate-600 font-mono text-sm leading-relaxed whitespace-pre">
{`TRS Agent
     │
     ▼
TRS Backend
     │
     │ POST /api/support/verify/
     ▼
Client Verification API
     │
     ▼
Service Layer
     │
     ├── Order Service
     ├── Payment Service
     ├── Refund Service
     ├── Account Service
     └── Subscription Service
     │
     ▼
Response Returned To TRS`}
                </pre>
              </div>
            </section>

          </main>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default IntegrationGuide;