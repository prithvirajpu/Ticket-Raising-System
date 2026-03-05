import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import DashboardLayout from "../../layouts/DashboardLayout"; // Adjust path
import api from "../../api/axios";

const AgentDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [agent, setAgent] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchAgent = async () => {
    try {
      const res = await api.get(`/auth/admin/agent/${id}/`);
      console.log('result', res);
      setAgent(res.data);
    } catch (err) {
      console.error(err);
      alert("Failed to load agent details");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAgent();
  }, [id]);

  if (loading) {
    return (
      <DashboardLayout title="Agent Details" subtitle="Loading...">
        <div className="flex justify-center items-center h-64">
          <p className="text-lg">Loading agent details...</p>
        </div>
      </DashboardLayout>
    );
  }

  if (!agent) {
    return (
      <DashboardLayout title="Agent Details" subtitle="Not found">
        <div className="flex justify-center items-center h-64">
          <p className="text-lg text-gray-500">No agent found</p>
        </div>
      </DashboardLayout>
    );
  }

  const handleBack = () => navigate(-1);

  return (
    <DashboardLayout
      title="Agent Application Details"
      headerAction={
        <button
          onClick={handleBack}
          className="bg-gray-700 text-white px-6 py-2 rounded-lg hover:bg-gray-800 transition-colors"
        >
          Back to List
        </button>
      }
    >
      <div className="bg-white p-8 rounded-xl shadow-lg border border-gray-100">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-8">
          <div>
            <h3 className="text-xl font-semibold text-gray-800 mb-4">Personal Information</h3>
            <div className="space-y-4">
              <p><strong className="text-gray-700">Full Name:</strong> {agent.full_name}</p>
              <p><strong className="text-gray-700">Email:</strong> {agent.email}</p>
              <p><strong className="text-gray-700">Phone:</strong> {agent.phone}</p>
              {/* <p><strong className="text-gray-700">Applied At:</strong> {new Date(agent.applied_at).toLocaleDateString()}</p> */}
              {agent.reviewed_at && (
                <p><strong className="text-gray-700">Reviewed At:</strong> {new Date(agent.reviewed_at).toLocaleDateString()}</p>
              )}
            </div>
          </div>

          <div>
            <h3 className="text-xl font-semibold text-gray-800 mb-4">Application Details</h3>
            <div className="space-y-4">
              <p><strong className="text-gray-700">Skills:</strong></p>
              <p className="bg-gray-50 p-3 rounded-lg">{agent.skills}</p>
              <p><strong className="text-gray-700">Status:</strong></p>
              <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                agent.status === 'APPROVED' ? 'bg-green-100 text-green-800' :
                agent.status === 'PENDING' ? 'bg-yellow-100 text-yellow-800' :
                'bg-red-100 text-red-800'
              }`}>
                {agent.status}
              </span>
            </div>
          </div>
        </div>

        {agent.resume && (
          <div className="mb-8 p-6 bg-blue-50 border-2 border-dashed border-blue-200 rounded-xl">
            <h3 className="text-lg font-semibold mb-4 text-blue-800">📄 Resume</h3>
            <a
              href={agent.resume}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-all duration-200"
            >
              👁️ View Resume
            </a>
          </div>
        )}

        {agent.certificates?.length > 0 && (
          <div className="mb-8">
            <h3 className="text-xl font-semibold mb-6 text-gray-800">
              📜 Certificates ({agent.certificates.length})
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {agent.certificates.map((url, index) => {
                const correctUrl = url.replace('/image/upload', '/raw/upload');
                return (
                  <div key={index} className="group">
                    <a
                      href={correctUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block p-6 border-2 border-gray-200 rounded-xl hover:border-blue-300 hover:shadow-xl transition-all duration-200 hover:-translate-y-1 bg-gradient-to-br from-white to-gray-50 group-hover:from-blue-50"
                    >
                      <div className="flex items-center space-x-3 mb-2">
                        <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center">
                          <span className="text-blue-600 font-bold text-lg">📄</span>
                        </div>
                        <span className="font-medium text-gray-900">Certificate {index + 1}</span>
                      </div>
                      <p className="text-sm text-gray-500">Click to view full document</p>
                    </a>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default AgentDetail;
