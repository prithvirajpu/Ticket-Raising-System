import { useEffect, useState } from 'react';
import DashboardLayout from '../../../layouts/DashboardLayout';
import { getProfile, updateClientProfile, updateProfile } from '../../../services/ticketService';
import Loader from '../../../components/modals/Loader';
import EditProfileModal from '../../../components/modals/EditProfileModal';
import { useAuth } from '../../../auth/AuthContext';
import { notifySuccess } from '../../../utils/notify';

const ProfilePage = () => {
    const { userRole } = useAuth();
    const [profile, setProfile] = useState({ name: '', phone: '', email: '' });
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);
    const [isModalOpen, setIsModalOpen] = useState(false);

    useEffect(() => {
        fetchProfile();
    }, []);

    const fetchProfile = async () => {
        setLoading(true);
        try {
            const res = await getProfile();
            const data = res.message;
            setProfile({
                name: data.name || '',
                phone: data.phone || '',
                email: data.email || '',
            });
        } catch (error) {
            console.error(error);
        } finally {
            setLoading(false);
        }
    };

    const handleUpdate = async (updatedData) => {
        console.log('updated data',updatedData)
        setSaving(true);
        try {
            if (userRole === "CLIENT") {
                await updateClientProfile(updatedData);
                notifySuccess('Profile updated successfully')
            } else {
                await updateProfile(updatedData);
                notifySuccess('Profile updated successfully')
            }

            setProfile(updatedData);
            setIsModalOpen(false);
        } catch (error) {
            console.error(error?.response?.data.errors?.details);
        } finally {
            setSaving(false);
        }
    };

    if (loading) return <Loader />;

    const avatarUrl = profile.name || profile.email
        ? `https://ui-avatars.com/api/?name=${encodeURIComponent(profile.name || profile.email.split('@')[0])}&background=6366f1&color=fff&bold=true&size=256`
        : 'https://ui-avatars.com/api/?name=User&background=6366f1&color=fff&bold=true&size=256';

    return (
        <DashboardLayout>
            <div className="min-h-screen bg-[#f8fafc] py-12 px-4 sm:px-6 lg:px-8">
                <div className="max-w-4xl mx-auto">
                    
                    {/* Header Section */}
                    <div className="mb-8 flex flex-col md:flex-row md:items-end md:justify-between gap-4">
                        <div>
                            <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">Account Settings</h1>
                            <p className="text-slate-500 mt-1">Manage your public profile and personal information.</p>
                        </div>
                        <button
                            onClick={() => setIsModalOpen(true)}
                            className="inline-flex items-center justify-center px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-xl transition-all shadow-md shadow-indigo-200 active:scale-95"
                        >
                            <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                            </svg>
                            Edit Profile
                        </button>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        
                        {/* Left Column: Avatar Card */}
                        <div className="lg:col-span-1">
                            <div className="bg-white rounded-3xl p-8 shadow-sm border border-slate-200 flex flex-col items-center text-center">
                                <div className="relative group">
                                    <div className="absolute -inset-1 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-full blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
                                    <img
                                        src={avatarUrl}
                                        alt="Profile"
                                        className="relative w-32 h-32 rounded-full border-4 border-white shadow-xl object-cover"
                                    />
                                    <div className="absolute bottom-1 right-1 w-7 h-7 bg-emerald-500 border-4 border-white rounded-full"></div>
                                </div>
                                <h2 className="mt-6 text-xl font-bold text-slate-900 uppercase tracking-tight">
                                    {profile.name || "New User"}
                                </h2>
                                <span className="mt-1 px-3 py-1 bg-indigo-50 text-indigo-700 text-xs font-bold rounded-full uppercase tracking-wider">
                                    Verified Member
                                </span>
                            </div>
                        </div>

                        {/* Right Column: Details Bento Grid */}
                        <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4">
                            
                            {/* Email Tile */}
                            <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm flex flex-col justify-between hover:border-indigo-200 transition-colors">
                                <div className="w-10 h-10 bg-indigo-50 rounded-xl flex items-center justify-center text-indigo-600 mb-4">
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                                    </svg>
                                </div>
                                <div>
                                    <p className="text-sm font-medium text-slate-400 uppercase tracking-widest">Email Address</p>
                                    <p className="text-lg font-semibold text-slate-800 mt-1 truncate">{profile.email}</p>
                                </div>
                            </div>

                            {/* Phone Tile */}
                            <div className="bg-white p-6 rounded-3xl border border-slate-200 shadow-sm flex flex-col justify-between hover:border-indigo-200 transition-colors">
                                <div className="w-10 h-10 bg-emerald-50 rounded-xl flex items-center justify-center text-emerald-600 mb-4">
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z" />
                                    </svg>
                                </div>
                                <div>
                                    <p className="text-sm font-medium text-slate-400 uppercase tracking-widest">Phone Number</p>
                                    <p className="text-lg font-semibold text-slate-800 mt-1">
                                        {profile.phone || <span className="text-slate-300 italic font-normal">Add phone</span>}
                                    </p>
                                </div>
                            </div>

                            {/* Wide Security Tile */}
                            <div className="md:col-span-2 bg-slate-900 p-6 rounded-3xl shadow-xl flex items-center justify-between">
                                <div className="flex items-center gap-4">
                                    <div className="w-12 h-12 bg-white/10 rounded-2xl flex items-center justify-center text-white backdrop-blur-md">
                                        <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04 inter-gradient" />
                                        </svg>
                                    </div>
                                    <div>
                                        <h3 className="text-white font-bold text-lg">Security & Privacy</h3>
                                        <p className="text-slate-400 text-sm">Your data is encrypted and secure.</p>
                                    </div>
                                </div>
                                
                            </div>
                        </div>
                    </div>

            
                </div>
            </div>

            <EditProfileModal
                isOpen={isModalOpen}
                onClose={() => setIsModalOpen(false)}
                initialData={profile}
                onSave={handleUpdate}
                saving={saving}
            />
        </DashboardLayout>
    );
};

export default ProfilePage;