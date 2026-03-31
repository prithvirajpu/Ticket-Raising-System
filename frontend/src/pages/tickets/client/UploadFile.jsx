import { useState } from 'react'
import DashboardLayout from '../../../layouts/DashboardLayout'
import { uploadDocument } from '../../../services/ticketService';
import Loader from '../../../components/modals/Loader';

const UploadFile = () => {
    const [files,setFiles]=useState({
                                    guidelines_doc: null,
                                    faq_doc: null,
                                    extra_doc: null })
    const [loading,setLoading]=useState(false);
    const handleChange=(e)=>{
        const {name,files:selectedFiles}=e.target
        setFiles((prev)=>({
            ...prev,[name]:selectedFiles[0]
        }))
    }
    const handleSubmit= async (e)=>{
        e.preventDefault();
        const formData=new FormData();
        formData.append('guidelines_doc',files.guidelines_doc)
        formData.append('faq_doc',files.faq_doc)
        if (files.extra_doc){
            formData.append('extra_doc',files.extra_doc)
        }
        setLoading(true);
        try {
            await uploadDocument(formData);
        } catch (error) {
            console.log(error)
        } finally{
            setLoading(false);
        }
    }
  return (
    <DashboardLayout
    title="Upload Documents" 
    subtitle="Share your knowledge base with the support team">
        <div className="max-w-xl mx-auto bg-white p-6 rounded-xl shadow mt-10">
                <h2 className="text-xl font-bold mb-4">Upload Documents</h2>

                <form onSubmit={handleSubmit} className="space-y-4">
                    
                    <div>
                        <label className="block text-sm mb-1">Guidelines Document *</label>
                        <input
                            type="file"
                            name="guidelines_doc"
                            onChange={handleChange}
                            required
                        />
                    </div>

                    <div>
                        <label className="block text-sm mb-1">FAQ Document *</label>
                        <input
                            type="file"
                            name="faq_doc"
                            onChange={handleChange}
                            required
                        />
                    </div>

                    <div>
                        <label className="block text-sm mb-1">Extra Document</label>
                        <input
                            type="file"
                            name="extra_doc"
                            onChange={handleChange}
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className="bg-black text-white px-4 py-2 rounded"
                    >
                        {loading ? "Uploading..." : "Upload"}
                    </button>
                </form>
            </div>
    </DashboardLayout>
  )
}

export default UploadFile
