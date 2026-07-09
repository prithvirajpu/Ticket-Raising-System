import axios from 'axios';

const api=axios.create({
    baseURL:'http://localhost:8000/api',
    withCredentials:true,
});

api.interceptors.request.use((config)=>{
    const token= localStorage.getItem('access');
    if (token){
        config.headers.Authorization=`Bearer ${token}`
    }
    return config
})

api.interceptors.response.use(
    (response) => response,
    async (error) => {
        const originalRequest = error.config;

        if (error.response?.status === 401 && !originalRequest._retry) {
            originalRequest._retry = true;

            try {
                const res = await axios.post(
                    "http://localhost:8000/api/auth/token/refresh/",
                    {},{withCredentials:true,}
                );

                const newAccess = res.data.access;
                localStorage.setItem("access", newAccess);

                originalRequest.headers.Authorization = `Bearer ${newAccess}`;
                return api(originalRequest);

            } catch (err) {
                localStorage.clear();
                window.location.href = "/";
                return Promise.reject(err);
            }
        }

        return Promise.reject(error);
    }
);

export default api