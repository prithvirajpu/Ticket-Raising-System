import api from "../../api/axios";

export const slaRulesInAdminSide = async () => {
    try {
        const res = await api.get('admins/sla-rules/')
        return res.data.data
    } catch (error) {
        console.log('Error in SLA rules admin:', error)
        throw error
    }
}

export const createSlaRuleInAdminSide = async (data) => {
    try {
        const res = await api.post(
            'admins/sla-rules/',
            data
        )
        return res.data
    } catch (error) {
        console.log('Error creating SLA rule:', error)
        throw error
    }
}

export const getUserData = async (page = 1) => {
    try {
        const res = await api.get(`/admins/users/?page=${page}`)
        return res
    } catch (error) {
        console.log('Error fetching users:', error)
        throw error
    }
}

export const assignHierarchy = async (payload) => {
  try {
    const res = await api.post(
      "/admins/assign-hierarchy/",
      payload
    );
    return res.data;
  } catch (err) {
    throw err;
  }
};

export const getAllUsers = async () => {
  try {
    const res = await api.get("/admins/users/all/");
    return res.data.data;
  } catch (err) {
    throw err;
  }
};
export const getHierarchy= async()=>{
    try {
        const res= await api.get("/admins/hierarchy/")
        return res.data       
    } catch (error) {
        console.log(error)
    }

}
export const getWithdrawRequests =async(page=1)=>{
    try {
        const res= await api.get(`/admins/wallet/requests/?page${page}`)
        return {
           message: res.data.data.message,
            paginator: res.data.paginator,
        }
    } catch (error) {
        console.log(error)
        console.log(error?.response?.data?.errors)
    }
}

export const approveWithdrawal = async(id)=>{
    try {
        const res = await api.post(
        `/admins/wallet/requests/${id}/approve/`
    )
    return res.data.data
    } catch (error) {
        console.log(error)
    }
}

export const rejectWithdrawal = async(id)=>{
    try {
        const res = await api.post(
        `/admins/wallet/requests/${id}/reject/`
    )
    return res.data.data
    } catch (error) {
        console.log(error)
    }
}
export const getAdminWalletTransactions = async(page=1)=>{
    try {
        const res = await api.get(`/admins/wallet-transactions/?page=${page}`)
        return {
            message: res.data.data.message,
            paginator: res.data.paginator,
        }
    } catch (error) {
        console.log(error)
        throw error
    }
}
export const getAdminDashboard = async(period='7d')=>{
    try {
        const res = await api.get(`/admins/dashboard/?period=${period}`)
        return res.data.data
    } catch (error) {
        console.log(error)
        throw error
    }
}
export const getRevenueDashboard  = async(salaryPage, subscriptionPage)=>{
    try {
        const res = await api.get(`/admins/finance/`,{
            params:{
                salary_page: salaryPage,
                subscription_page: subscriptionPage,
            }
        })
        return res.data.data
    } catch (error) {
        console.log(error)
        throw error
    }
}
export const downloadFinanceReport = async () => {
    try {
        const response = await api.get(
            "/admins/finance/export/",
            {
                responseType: "blob",
            }
        );

        const url = window.URL.createObjectURL(
            new Blob([response.data])
        );

        const link = document.createElement("a");
        link.href = url;
        link.download = "finance_report.csv";

        document.body.appendChild(link);
        link.click();

        link.remove();
        window.URL.revokeObjectURL(url);

    } catch (error) {
        notifyError(
            error?.response?.data?.errors?.details ||
            "Unable to download report."
        );
    }
};

export const downloadDashboardReport = async (period = "7d") => {
    try {
        const response = await api.get(
            `/admins/dashboard/export/?period=${period}`,
            {
                responseType: "blob",
            }
        );

        const url = window.URL.createObjectURL(
            new Blob([response.data])
        );

        const link = document.createElement("a");

        link.href = url;
        link.download = `dashboard_report_${period}.csv`;

        document.body.appendChild(link);

        link.click();

        link.remove();

        window.URL.revokeObjectURL(url);

    } catch (error) {
        notifyError(
            error?.response?.data?.errors?.details ||
            "Unable to download dashboard report."
        );
    }
};
export const createSubscriptionPlan = async (planData) => {
    const response = await api.post("/admins/plans/",planData);
    return response.data;
};

export const getSubscriptionPlansAdmin = async () => {
    const response = await api.get("/admins/plans/");
    return response.data;
};

export const updateSubscriptionPlan = async (planId, data) => {
    const response = await api.patch(`/admins/plans/${planId}/`, data);
    return response.data;
};

export const getSalaryConfig = async () => {
    try {
        const res = await api.get("/admins/salary-config/");
        return res.data
    } catch (error) {
        console.log(error.response?.data?.errors ||
                "Something went wrong",)
        throw error
    }
};

export const createSalaryConfig  = async (payload) => {
    try {
        const res = await api.post("/admins/salary-config/",payload);
        notifySuccess('Created successfully')
        return res.data
    } catch (error) {
        console.log(error.response?.data?.errors ||
        "Something went wrong",)
        throw error
    }
};

export const updateSalaryConfig  = async (payload) => {
    try {
        const res = await api.patch("/admins/salary-config/",payload);
        notifySuccess('Successfully updated')
        return res.data
    } catch (error) {
        console.log(error.response?.data?.errors ||
        "Something went wrong",)
        throw error
    }
};