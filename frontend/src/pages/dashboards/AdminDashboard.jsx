import DashboardLayout from "../../layouts/DashboardLayout";
import StatsCard from "../../components/StatsCard";

const AdminDashboard = () => {
  return (
    <DashboardLayout title="Admin Dashboard">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatsCard label="Total Users" value="120" />
        <StatsCard label="Pending Approvals" value="5" />
        <StatsCard label="Total Tickets" value="340" />
      </div>
    </DashboardLayout>
  );
};

export default AdminDashboard;
