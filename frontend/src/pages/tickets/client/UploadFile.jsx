import { useState } from 'react';
import { Upload, FileText, CheckCircle2, Loader2 } from 'lucide-react';
import DashboardLayout from '../../../layouts/DashboardLayout';
import { uploadDocument } from '../../../services/ticketService';
import { notifyInfo, notifySuccess } from '../../../utils/notify';

const UploadFile = () => {
    const [files, setFiles] = useState({
        guidelines_doc: null,
        faq_doc: null,
        extra_doc: null
    });
    const [loading, setLoading] = useState(false);

    const handleChange = (e) => {
        const { name, files: selectedFiles } = e.target;
        setFiles((prev) => ({
            ...prev,
            [name]: selectedFiles[0]
        }));
    };

    const handleSubmit = async (e) => {
    e.preventDefault();

    // ✅ REQUIRED VALIDATION
    if (!files.guidelines_doc || !files.faq_doc) {
        notifyInfo("Company Overview and FAQs are required");
        return;
    }

    const formData = new FormData();
    Object.keys(files).forEach(key => {
        if (files[key]) formData.append(key, files[key]);
    });

    setLoading(true);
    try {
        await uploadDocument(formData);
        notifySuccess('Documents Uploaded successfully');
        setFiles({
        guidelines_doc: null,
        faq_doc: null,
        extra_doc: null
    });
    } catch (error) {
        notifyInfo(
        error.response?.data?.errors?.details ||
        "Failed to upload documents."
    );
    } finally {
        setLoading(false);
    }
};

const isFormValid = files.guidelines_doc && files.faq_doc;

    // Helper component for the Upload Card
    const UploadCard = ({ title, name, currentFile }) => (
        <div className="flex flex-col items-center p-6 bg-white border border-gray-100 rounded-2xl shadow-sm hover:shadow-md transition-shadow text-center min-h-[250px] justify-between">
            <div className="bg-blue-50 p-4 rounded-full">
                <FileText className="w-8 h-8 text-blue-500" />
            </div>
            <div>
                <h3 className="font-semibold text-gray-800 text-lg">{title}</h3>
                <p className="text-sm text-gray-400 mt-1">
                    {currentFile ? currentFile.name : "Click to upload"}
                </p>
            </div>
            <label className="cursor-pointer bg-gray-50 border border-gray-200 hover:bg-gray-100 px-6 py-2 rounded-lg flex items-center gap-2 transition-colors">
                <Upload className="w-4 h-4 text-blue-600" />
                <span className="text-sm font-medium text-gray-700">Upload</span>
                <input type="file" name={name} className="hidden" onChange={handleChange} />
            </label>
        </div>
    );

    return (
        <DashboardLayout 
            title="Upload Documents" 
            subtitle="Share your knowledge base with the support team"
        >
            <div className="max-w-5xl mx-auto px-4 py-8">
                {loading && (
                    <div className="flex flex-col items-center gap-2">
                        <Loader2 className="w-8 h-8 animate-spin text-blue-600" />
                        <p className="text-sm text-gray-600">Uploading...</p>
                    </div>
                    )}
                
                {/* 1. Upload Grid Section */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
                    <UploadCard title="Company Overview" name="guidelines_doc" currentFile={files.guidelines_doc} />
                    <UploadCard title="FAQs" name="faq_doc" currentFile={files.faq_doc} />
                    <UploadCard title="Product Guide" name="extra_doc" currentFile={files.extra_doc} />
                </div>

                {/* Submit Trigger */}
                <div className="flex justify-center mb-16">
                    <button 
                        onClick={handleSubmit}
                        disabled={loading || !isFormValid}
                        className="bg-blue-600 hover:bg-blue-700 text-white px-10 py-3 rounded-full font-semibold shadow-lg disabled:opacity-50 transition-all"
                    >
                        {loading ? "Processing..." : "Save Knowledge Base"}
                    </button>
                </div>

            </div>
        </DashboardLayout>
    );
};

export default UploadFile;