import { useEffect, useState } from 'react';
import DashboardLayout from '../../../layouts/DashboardLayout';
import { getClientDocs } from '../../../services/ticketService';
import { useParams } from 'react-router-dom';
import getPreviewUrl from '../../../utils/getPreviewUrl'

const ClientDocumentsPage = () => {
    const { client_id } = useParams();
    const [docs, setDocs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        if (!client_id) {
            setError("Client ID is missing in the URL");
            setLoading(false);
            return;
        }
        fetchDocs();
    }, [client_id]);

    const fetchDocs = async () => {
        setLoading(true);
        setError(null);

        try {
            const res = await getClientDocs(client_id);
            console.log("Full Response:", res);

            // Safe handling for different response shapes
            const data = res?.message || res?.data?.message || res?.data || [];
            setDocs(Array.isArray(data) ? data : []);
        } catch (err) {
            console.error("Fetch error:", err.response?.data || err.message);
            setError(err.response?.data?.detail || "Failed to load documents");
            setDocs([]);
        } finally {
            setLoading(false);
        }
    };

    if (loading) return <DashboardLayout><div className="p-10 text-center">Loading client documents...</div></DashboardLayout>;
    if (error) return <DashboardLayout><div className="p-10 text-center text-red-600">{error}</div></DashboardLayout>;

    return (
        <DashboardLayout>
            <div className="max-w-3xl mx-auto mt-10 space-y-4">
                <h2 className="text-xl font-bold">Client Documents</h2>

                {docs.length === 0 ? (
                    <p className="text-gray-500">No documents available for this client.</p>
                ) : (
                    docs.map((doc, index) => (
                        
    <div key={index} className="border p-4 rounded space-y-4">

        <div>
            {console.log("Guidelines URL:", getPreviewUrl(doc.guidelines_doc))}
  {console.log("FAQ URL:", getPreviewUrl(doc.faq_doc))}
  {console.log("Extra URL:", getPreviewUrl(doc.extra_doc))}
            <p className="font-semibold">Guidelines</p>
            <a
  href={doc.guidelines_doc} // direct link in case iframe fails
  target="_blank"
  rel="noopener noreferrer"
>
  Open PDF in new tab
</a>
            
            <iframe
                src={getPreviewUrl(doc.guidelines_doc)}
                width="100%"
                height="400px"
                title="Guidelines PDF"
                className="border rounded"
            />
        </div>

        <div>
            <p className="font-semibold">FAQ</p>
            <a href={getPreviewUrl(doc.faq_doc)} target="_blank" rel="noopener noreferrer">
  Open FAQ PDF
</a>
            <iframe
                src={getPreviewUrl(doc.faq_doc)}
                width="100%"
                height="400px"
                title="FAQ PDF"
                className="border rounded"
            />
        </div>

        {doc.extra_doc && (
            <div>
                <p className="font-semibold">Extra</p>
                <iframe
                    src={getPreviewUrl(doc.extra_doc)}
                    width="100%"
                    height="400px"
                    title="Extra PDF"
                    className="border rounded"
                />
            </div>
        )}

    </div>
))
                )}
            </div>
        </DashboardLayout>
    );
};

export default ClientDocumentsPage;