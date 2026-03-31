import  { useEffect, useState } from 'react'
import DashboardLayout from '../../../layouts/DashboardLayout'
import { getProfile, updateProfile } from '../../../services/ticketService'
import Loader from '../../../components/modals/Loader'
import EditProfileModal from '../../../components/modals/EditProfileModal'

const ProfilePage = () => {
    const [profile,setProfile]=useState({'name':'','phone':'',"email":''})
    const [loading,setLoading]=useState(false)
    const [saving,setSaving]=useState(false)

    const [isModalOpen, setIsModalOpen] = useState(false);

    useEffect(()=>{
        fetchProfile();
    },[])

    const fetchProfile=async()=>{
        setLoading(true)
        try {
            const res= await getProfile();
            const data=res.message
            setProfile({
                name:data.name || '',
                phone:data.phone || '',
                email:data.email || '',
            })
        } catch (error) {
            console.log(error)
        } finally {
            setLoading(false)
        }
    }

    const handleUpdate = async(updatedData)=>{
        setSaving(true)
        try {
            await updateProfile(updatedData);
            await fetchProfile()
            setProfile(updatedData)
            setIsModalOpen(false);
        } catch (error) {
            console.log(error)
        } finally {
            setSaving(false);
        }
    }

    if (loading) return <Loader />

  return (
    <DashboardLayout>
            <div className="bg-white border rounded-2xl p-6 shadow-sm space-y-6 max-w-2xl mx-auto mt-10">
                <div className="flex justify-between items-center border-b pb-4">
                    <h2 className="text-xl font-bold">Profile Details</h2>
                    <button
                        onClick={() => setIsModalOpen(true)}
                        className="px-5 py-2 bg-black text-white text-sm rounded-lg hover:bg-gray-800"
                    >
                        Edit Profile
                    </button>
                </div>

                <div className="grid grid-cols-1 gap-4">
                    <div>
                        <p className="text-gray-400 text-xs uppercase tracking-wider">Full Name</p>
                        <p className="font-semibold text-gray-800">{profile.name || profile.email.split('@')[0]}</p>
                    </div>
                    <div>
                        <p className="text-gray-400 text-xs uppercase tracking-wider">Email Address</p>
                        <p className="font-semibold text-gray-800">{profile.email}</p>
                    </div>
                    <div>
                        <p className="text-gray-400 text-xs uppercase tracking-wider">Phone Number</p>
                        <p className="font-semibold text-gray-800">{profile.phone || "Not provided"}</p>
                    </div>
                </div>
            </div>

            {/* Calling the separate Modal Component */}
            <EditProfileModal
                isOpen={isModalOpen} 
                onClose={() => setIsModalOpen(false)}
                initialData={profile}
                onSave={handleUpdate}
                saving={saving}
            />
        </DashboardLayout>
  )
}

export default ProfilePage
