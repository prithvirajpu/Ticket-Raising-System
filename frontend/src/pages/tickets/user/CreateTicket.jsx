import { useNavigate } from 'react-router-dom'
import { createTicket } from '../../../services/ticketService'
import { useState } from 'react'
import Loader from '../../../components/modals/Loader'
import DashboardLayout from '../../../layouts/DashboardLayout'
import { ArrowLeft } from 'lucide-react'; 
import { notifySuccess } from '../../../utils/notify'

const CreateTicket = () => {
    const navigate = useNavigate()
    const [formData, setFormData] = useState({
        subject: '',
        description: '',
        priority: 'LOW',
        issue_type: ''
    })
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')

    const handleChange = (e) => {
        setFormData({
            ...formData, [e.target.name]: e.target.value
        })
    }

    const handleSubmit = async (e) => {
    e.preventDefault();

    if (!formData.subject.trim() || !formData.issue_type.trim() || !formData.description.trim()) {
        setError("Please fill all required fields");
        return;
    }

    try {
        setLoading(true);
        setError('');
        await createTicket(formData);
        navigate('/user/tickets');
        notifySuccess('Ticket created successfully !')
    } catch (error) {
        setError(error.response?.data?.details || 'something went wrong');
    } finally {
        setLoading(false);
    }
};
const isFormValid =
    formData.subject.trim() &&
    formData.issue_type.trim() &&
    formData.description.trim();

    return (
        <DashboardLayout>
            <div className='bg-white font-sans'>
                {loading && <Loader />}
                
                <div className="max-w-3xl mx-auto"> 
                    {/* Header Section - Tightened margins */}
                    <div className="flex items-center gap-4 mb-6">
                        <button onClick={() => navigate(-1)} className="text-gray-800 hover:text-black">
                            <ArrowLeft size={22} />
                        </button>
                        <div>
                            <h1 className="text-2xl font-bold text-gray-900 leading-tight">Create New Ticket</h1>
                            <p className="text-xs text-gray-400">Submit a support request</p>
                        </div>
                    </div>

                    {/* Main Card - Reduced internal padding from p-8 to p-6 */}
                    <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-sm">
                        <div className="mb-5 border-b border-gray-50 pb-4">
                            <h2 className="text-lg font-bold text-gray-800">Ticket Details</h2>
                            <p className="text-xs text-gray-400">Provide details about your issue or request</p>
                        </div>

                        {error && (
                            <div className='mb-4 p-2 text-sm bg-red-50 text-red-600 border border-red-100 rounded-lg'>
                                {error}
                            </div>
                        )}

                        {/* Reduced spacing from space-y-6 to space-y-4 */}
                        <form onSubmit={handleSubmit} className='space-y-4'>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                {/* Title / Subject */}
                                <div className="md:col-span-2">
                                    <label className="block text-xs font-bold text-gray-700 mb-1.5 uppercase tracking-wider">
                                        Title *
                                    </label>
                                    <input 
                                        type="text" 
                                        name='subject' 
                                        placeholder="Brief description of you issue..."
                                        value={formData.subject} 
                                        onChange={handleChange}
                                        className='w-full px-3 py-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:ring-1 focus:ring-gray-300 focus:outline-none text-sm placeholder-gray-400' 
                                    />
                                </div>

                                {/* Company / Issue Type */}
                                <div>
                                    <label className="block text-xs font-bold text-gray-700 mb-1.5 uppercase tracking-wider">
                                        Company *
                                    </label>
                                    <input 
                                        type="text" 
                                        name="issue_type" 
                                        placeholder="Enter your company"
                                        value={formData.issue_type} 
                                        onChange={handleChange}
                                        className="w-full px-3 py-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:ring-1 focus:ring-gray-300 focus:outline-none text-sm"
                                    />
                                </div>

                                {/* Priority Selection */}
                                <div>
                                    <label className="block text-xs font-bold text-gray-700 mb-1.5 uppercase tracking-wider">
                                        Priority
                                    </label>
                                    <select 
                                        name="priority" 
                                        value={formData.priority} 
                                        onChange={handleChange}
                                        className="w-full px-3 py-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:ring-1 focus:ring-gray-300 focus:outline-none text-sm appearance-none"
                                    >
                                        <option value="LOW">Low</option>
                                        <option value="MEDIUM">Medium</option>
                                        <option value="HIGH">High</option>
                                    </select>
                                </div>
                            </div>

                            {/* Description */}
                            <div>
                                <label className="block text-xs font-bold text-gray-700 mb-1.5 uppercase tracking-wider">
                                    Description *
                                </label>
                                <textarea 
                                    name="description" 
                                    placeholder="Provide detailed information about your issue..."
                                    value={formData.description} 
                                    onChange={handleChange} 
                                    rows={4}
                                    className="w-full px-3 py-2.5 bg-gray-50 border border-gray-200 rounded-lg focus:ring-1 focus:ring-gray-300 focus:outline-none text-sm"
                                />
                            </div>

                            {/* Action Buttons - Tightened padding */}
                            <div className="flex items-center gap-3 pt-2">
                                <button 
                                    type='submit' 
                                    disabled={loading || !isFormValid}  
                                    className="px-6 py-2.5 bg-black text-white text-sm font-bold rounded-lg hover:bg-gray-800 transition-colors disabled:bg-gray-400"
                                >
                                    {loading ? 'Submitting...' : 'Submit Ticket'}
                                </button>
                                <button 
                                    type='button'
                                    onClick={() => navigate(-1)}
                                    className="px-6 py-2.5 bg-white border border-gray-300 text-gray-700 text-sm font-medium rounded-lg hover:bg-gray-50 transition-colors"
                                >
                                    cancel
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        </DashboardLayout>
    )
}

export default CreateTicket