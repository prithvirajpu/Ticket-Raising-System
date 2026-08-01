import axios from "axios";

const BASE_API=import.meta.env.VITE_API_URL

export const refreshAccessToken = async (updateAccessToken) => {
    console.log("Refreshing access token...");

    const res = await axios.post(
        `${BASE_API}/api/auth/token/refresh/`,
        {},
        { withCredentials: true }
    );

    const newToken = res.data.access;

    if (updateAccessToken) {
        updateAccessToken(newToken);
    } else {
        localStorage.setItem("access", newToken);
    }

    return newToken;
};