from django.contrib.auth import get_user_model
User=get_user_model()

def get_user_dashboard():
    return {
        "total": User.objects.count(),
        "customers": User.objects.filter(role="USER").count(),
        "clients": User.objects.filter(role="CLIENT").count(),
        "agents": User.objects.filter(role="AGENT").count(),
        "team_leads": User.objects.filter(role="TEAM_LEAD").count(),
        "managers": User.objects.filter(role="MANAGER").count(),
    }