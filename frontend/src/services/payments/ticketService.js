import api from "../../api/axios";

export const connectStripe =async()=>{
    try {
        const res= await api.post(`/payments/connect-account/`)
        return res.data.data
    } catch (error) {
        console.log(error)
    }
}
export const getWalletMoney =async()=>{
    try {
        const res= await api.get(`/payments/wallet/`)
        return res.data.data
    } catch (error) {
        console.log(error)
    }
}
export const getWalletTransactions =async(page=1)=>{
    try {
        const res= await api.get(`/payments/wallet/transactions/?page=${page}`)
        return res.data
    } catch (error) {
        console.log(error)
    }
}
export const createWithdrawRequest =async(amount)=>{
    try {
        const res= await api.post(`/payments/withdraw/`,amount)
        return res.data.data
    } catch (error) {
        console.log(error)
        notifyError(error?.response?.data?.errors?.details)
        throw error
    }
}