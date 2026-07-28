import axios from "axios";

export const refreshAccessToken = async (updateAccessToken) => {
    console.log("Refreshing access token...");

    const res = await axios.post(
        "http://localhost:8080/api/auth/token/refresh/",
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