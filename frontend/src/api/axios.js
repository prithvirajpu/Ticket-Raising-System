import axios from 'axios';

const api=axios.create({
    baseURL:'http://localhost:8000/api',
    withCredentials:true,//enable cookies so httponly cookie accessible
});

api.interceptors.request.use((config)=>{
    const token= localStorage.getItem('access');
    if (token){
        config.headers.Authorization=`Bearer ${token}`
    }
    return config
})

// api.interceptors.response.use(
//     (response)=>response,
//         async (error)=>{
//             if (error.response?.status===401 && !error.config._retry){
//                 error.config._retry=true;
//                 const refresh=localStorage.getItem('refresh');
//                 const res=await api.post('/auth/token/refresh/',{refresh});
//                 localStorage.setItem('access',res.data.access);
//                 error.config.headers.Authorization=`Bearer ${res.data.access}`;
//                 return api(error.config);
//             }
//             return Promise.reject(error);
//         }
// )

export default api