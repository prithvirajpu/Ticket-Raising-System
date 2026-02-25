export const redirectByRole=(role)=>{
    switch (role){
        case 'ADMIN':
            return "/admin/dashboard"
        case 'MANAGER':
            return "/manager/dashboard"
        case 'TEAM_LEAD':
            return "/team-lead/dashboard"
        case 'AGENT':
            return "/agent/dashboard"
        case 'CLIENT':
            return "/client/dashboard"
        default:
            return "/user/dashboard"
    }
};