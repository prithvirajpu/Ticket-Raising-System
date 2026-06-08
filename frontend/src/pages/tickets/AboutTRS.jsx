import React from "react";
import {
  Shield,
  Users,
  Briefcase,
  Headphones,
  Building2,
  CheckCircle,
  PhoneCall,
  UserCheck, // Added for the SSO End User integration
} from "lucide-react";
import DashboardLayout from "../../layouts/DashboardLayout";

const AboutTRS = () => {
  return (
    <DashboardLayout
      title="About TRS"
      subtitle="Learn more about the Ticket Resolution System"
    >
      <div className="max-w-5xl mx-auto space-y-10 pb-12 text-slate-800 antialiased">
        
        {/* Introduction & Mission */}
        <div className="grid md:grid-cols-3 gap-6">
          <div className="md:col-span-2 bg-white rounded-2xl border border-slate-200 p-8 shadow-sm flex flex-col justify-between">
            <div>
              <h2 className="text-2xl font-bold tracking-tight text-slate-900 mb-4">
                What is TRS?
              </h2>
              <p className="text-slate-600 leading-relaxed mb-4">
                TRS (Ticket Resolution System) is a centralized customer support
                platform designed to help organizations efficiently manage,
                assign, track, and resolve customer issues.
              </p>
              <p className="text-slate-600 leading-relaxed">
                The platform connects clients, support agents, team leads,
                managers, and administrators in a structured workflow that
                ensures customer concerns are addressed quickly and transparently.
              </p>
            </div>
          </div>

          <div className="bg-gradient-to-br from-slate-900 to-slate-800 text-white rounded-2xl p-8 shadow-sm flex flex-col justify-between border border-slate-800">
            <div>
              <h2 className="text-xl font-bold tracking-tight mb-4 text-white">
                Our Mission
              </h2>
              <p className="text-slate-300 text-sm leading-relaxed">
                Our mission is to simplify customer support operations through
                intelligent ticket management, SLA monitoring, automated
                assignments, escalations, and real-time collaboration.
              </p>
            </div>
            <div className="pt-6 border-t border-slate-700/50 mt-6 flex items-center justify-between text-xs text-slate-400">
              <span>Enterprise Grade</span>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            </div>
          </div>
        </div>

        {/* How It Works */}
        <div className="bg-white rounded-2xl border border-slate-200 p-8 shadow-sm">
          <h2 className="text-xl font-bold tracking-tight text-slate-900 mb-8">
            How TRS Works
          </h2>

          <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-4 relative">
            {[
              "E-commerce SSO Handoff",
              "Ticket Created in TRS",
              "Agent Investigates",
              "Escalation if Required",
              "Resolution & Closure",
            ].map((step, index) => (
              <div
                key={index}
                className="bg-slate-50/60 rounded-xl p-5 border border-slate-100 relative flex flex-col items-center text-center group hover:border-slate-200 transition-all"
              >
                <div className="w-10 h-10 rounded-full bg-blue-50 text-blue-600 flex items-center justify-center text-sm font-bold mb-4 shadow-sm group-hover:bg-blue-600 group-hover:text-white transition-colors">
                  {index + 1}
                </div>
                <p className="text-sm font-medium text-slate-700 leading-snug">{step}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Roles in TRS */}
        <div className="bg-white rounded-2xl border border-slate-200 p-8 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-8">
            <h2 className="text-xl font-bold tracking-tight text-slate-900">
              Roles in TRS
            </h2>
            <span className="text-xs font-medium px-2.5 py-1 rounded-full bg-slate-100 text-slate-600 border border-slate-200/60 self-start">
              Role-Based Access Control
            </span>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-12 gap-5">
            
            {/* New User Role Positioned First As Core Customer Entry */}
            <div className="border border-blue-100 rounded-xl p-6 hover:shadow-md hover:border-blue-200 transition-all lg:col-span-4 bg-blue-50/10">
              <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center mb-4 border border-blue-100">
                <UserCheck className="w-5 h-5 text-blue-600" />
              </div>
              <h3 className="font-bold text-slate-900 mb-2 flex items-center gap-2">
                User <span className="text-xs font-normal text-blue-600 bg-blue-50 px-1.5 py-0.5 rounded">End User</span>
              </h3>
              <p className="text-sm text-slate-600 leading-relaxed">
                The e-commerce customer belonging to a client platform. They transition to TRS seamlessly using secure, single sign-on (SSO) authentication to open and monitor their support tickets.
              </p>
            </div>

            <div className="border border-slate-200/80 rounded-xl p-6 hover:shadow-md hover:border-slate-300 transition-all lg:col-span-4 bg-white">
              <div className="w-10 h-10 rounded-lg bg-red-50 flex items-center justify-center mb-4">
                <Shield className="w-5 h-5 text-red-500" />
              </div>
              <h3 className="font-bold text-slate-900 mb-2">Admin</h3>
              <p className="text-sm text-slate-600 leading-relaxed">
                Manages the entire platform, subscriptions, users,
                departments, plans, SLAs, and system-wide configurations.
              </p>
            </div>

            <div className="border border-slate-200/80 rounded-xl p-6 hover:shadow-md hover:border-slate-300 transition-all lg:col-span-4 bg-white">
              <div className="w-10 h-10 rounded-lg bg-indigo-50 flex items-center justify-center mb-4">
                <Briefcase className="w-5 h-5 text-indigo-500" />
              </div>
              <h3 className="font-bold text-slate-900 mb-2">Manager</h3>
              <p className="text-sm text-slate-600 leading-relaxed">
                Oversees teams, monitors performance, reviews escalations,
                and ensures SLA compliance.
              </p>
            </div>

            <div className="border border-slate-200/80 rounded-xl p-6 hover:shadow-md hover:border-slate-300 transition-all lg:col-span-4 bg-white">
              <div className="w-10 h-10 rounded-lg bg-orange-50 flex items-center justify-center mb-4">
                <Users className="w-5 h-5 text-orange-500" />
              </div>
              <h3 className="font-bold text-slate-900 mb-2">Team Lead</h3>
              <p className="text-sm text-slate-600 leading-relaxed">
                Supervises agents, distributes workloads, reviews tickets,
                and handles escalated issues.
              </p>
            </div>

            <div className="border border-slate-200/80 rounded-xl p-6 hover:shadow-md hover:border-slate-300 transition-all lg:col-span-4 bg-white">
              <div className="w-10 h-10 rounded-lg bg-emerald-50 flex items-center justify-center mb-4">
                <Headphones className="w-5 h-5 text-emerald-500" />
              </div>
              <h3 className="font-bold text-slate-900 mb-2">Agent</h3>
              <p className="text-sm text-slate-600 leading-relaxed">
                Investigates customer issues, communicates with clients,
                updates ticket status, and resolves problems.
              </p>
            </div>

            <div className="border border-slate-200/80 rounded-xl p-6 hover:shadow-md hover:border-slate-300 transition-all lg:col-span-4 bg-white">
              <div className="w-10 h-10 rounded-lg bg-blue-50 flex items-center justify-center mb-4">
                <Building2 className="w-5 h-5 text-blue-500" />
              </div>
              <h3 className="font-bold text-slate-900 mb-2">Client</h3>
              <p className="text-sm text-slate-600 leading-relaxed">
                Organizations (such as e-commerce platforms) that integrate with TRS and manage customer support requests through the platform.
              </p>
            </div>
          </div>
        </div>

        {/* Features & Benefits */}
        <div className="grid lg:grid-cols-12 gap-6">
          
          {/* Key Features */}
          <div className="bg-white rounded-2xl border border-slate-200 p-8 shadow-sm lg:col-span-7">
            <h2 className="text-xl font-bold tracking-tight text-slate-900 mb-6">
              Key Features
            </h2>
            <div className="grid sm:grid-cols-2 gap-3">
              {[
                { label: "Smart Ticket Management", type: "core" },
                { label: "SLA Monitoring", type: "core" },
                { label: "Automatic Ticket Assignment", type: "core" },
                { label: "Escalation Workflow", type: "core" },
                { label: "Real-Time Notifications", type: "core" },
                { label: "Agent Performance Tracking", type: "core" },
                { label: "Client Integration APIs", type: "core" },
                { label: "Audit Logs & Reporting", type: "core" },
                { label: "Role-Based Access Control", type: "core" },
                { label: "Live Chat & Collaboration", type: "core" },
                { label: "Voice Call Integration", type: "call" },
                { label: "SSO Style Secure Login", type: "sso" }, // Incorporated SSO feature
              ].map((feature) => (
                <div
                  key={feature.label}
                  className={`flex items-center gap-3 border rounded-xl p-3 text-sm font-medium ${
                    feature.type === "call" || feature.type === "sso"
                      ? "bg-blue-50/50 border-blue-200 text-blue-900"
                      : "border-slate-100 bg-slate-50/30 text-slate-700"
                  }`}
                >
                  {feature.type === "call" ? (
                    <PhoneCall className="w-4 h-4 text-blue-600 shrink-0" />
                  ) : feature.type === "sso" ? (
                    <UserCheck className="w-4 h-4 text-blue-600 shrink-0" />
                  ) : (
                    <CheckCircle className="w-4 h-4 text-emerald-500 shrink-0" />
                  )}
                  <span className="truncate">{feature.label}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Benefits */}
          <div className="bg-white rounded-2xl border border-slate-200 p-8 shadow-sm lg:col-span-5 flex flex-col justify-between">
            <div>
              <h2 className="text-xl font-bold tracking-tight text-slate-900 mb-6">
                Benefits of Using TRS
              </h2>
              <ul className="space-y-4">
                {[
                  "Faster ticket resolution.",
                  "Improved customer satisfaction.",
                  "Direct call routing & quick voice context.",
                  "Frictionless SSO handoff from e-commerce platforms.", // Incorporated SSO Benefit
                  "Better team collaboration.",
                  "SLA-driven accountability.",
                  "Reduced manual workload.",
                  "Complete visibility into support operations.",
                  "Scalable support infrastructure.",
                ].map((benefit, i) => (
                  <li key={i} className="flex items-start gap-3 text-sm text-slate-600">
                    <span className="w-1.5 h-1.5 rounded-full bg-slate-400 mt-2 shrink-0" />
                    <span className="leading-normal">{benefit}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Technical Highlights / Highlights Info Bar */}
        <div className="grid md:grid-cols-2 gap-4">
          <div className="bg-blue-50/40 border border-blue-100 rounded-2xl p-6 flex items-center gap-4 shadow-sm">
            <div className="w-12 h-12 rounded-xl bg-blue-600 text-white flex items-center justify-center shrink-0 shadow-md shadow-blue-500/20">
              <PhoneCall className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-900 mb-0.5">Integrated Voice Support Built-In</h4>
              <p className="text-xs text-slate-600 leading-relaxed">
                Agents can initiate and receive real-time customer support calls directly inside the TRS portal tracking workspace.
              </p>
            </div>
          </div>

          <div className="bg-indigo-50/40 border border-indigo-100 rounded-2xl p-6 flex items-center gap-4 shadow-sm">
            <div className="w-12 h-12 rounded-xl bg-indigo-600 text-white flex items-center justify-center shrink-0 shadow-md shadow-indigo-500/20">
              <UserCheck className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-bold text-slate-900 mb-0.5">Federated SSO Login Flow</h4>
              <p className="text-xs text-slate-600 leading-relaxed">
                E-commerce users cross over to TRS without creating secondary passwords, directly retaining their initial active buyer profile context.
              </p>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-2xl p-8 text-center shadow-lg shadow-blue-500/10 border border-blue-700/30">
          <h2 className="text-xl font-bold mb-3 text-white tracking-tight">
            Ticket Resolution System (TRS)
          </h2>
          <p className="max-w-2xl mx-auto text-blue-100 text-sm leading-relaxed">
            A complete enterprise-grade support management platform that
            empowers organizations to deliver efficient, transparent,
            and SLA-compliant customer service experiences.
          </p>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default AboutTRS;