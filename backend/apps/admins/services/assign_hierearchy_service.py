import logging
from django.db import transaction
from rest_framework import status
from apps.accounts.models import User
from apps.tickets.models import ClientProfile
from apps.core_app.constants import UserRole

logger = logging.getLogger(__name__)


def assign_hierarchy_service(data):

    user_id = data.get("user_id")
    manager_id = data.get("manager_id")
    team_lead_id = data.get("team_lead_id")

    logger.info(f"INPUT -> user_id={user_id}, manager_id={manager_id}, team_lead_id={team_lead_id}")

    # --------------------------
    # VALIDATE USER
    # --------------------------
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return {
            "data": None,
            "errors": {"details": "User not found"},
            "status": status.HTTP_404_NOT_FOUND
        }

    logger.info(
        f"BEFORE UPDATE -> user_id={user.id}, role={user.role}, "
        f"manager_id={user.manager_id}, team_lead_id={user.team_lead_id}"
    )

    # --------------------------
    # NORMALIZE INPUT
    # --------------------------
    def normalize(val):
        if val in ["", None, "null", "None"]:
            return None
        return val

    manager_id = normalize(manager_id)
    team_lead_id = normalize(team_lead_id)

    # --------------------------
    # 🔥 SELF REFERENCE IGNORE (IMPORTANT FIX)
    # --------------------------
    if manager_id and int(manager_id) == user.id:
        logger.info("Ignoring self manager assignment")
        manager_id = None

    if team_lead_id and int(team_lead_id) == user.id:
        logger.info("Ignoring self team_lead assignment")
        team_lead_id = None

    with transaction.atomic():

        updated = False

        # ==================================================
        # CLIENT
        # ==================================================
        if user.role == UserRole.CLIENT:

            logger.info("Processing CLIENT hierarchy assignment")

            if manager_id:
                manager = User.objects.get(id=manager_id, role=UserRole.MANAGER)
                user.manager = manager
                updated = True
                logger.info(f"Assigned MANAGER -> {manager.id}")
            else:
                user.manager = None

            if team_lead_id:
                team_lead = User.objects.get(id=team_lead_id, role=UserRole.TEAM_LEAD)
                user.team_lead = team_lead
                updated = True
                logger.info(f"Assigned TEAM_LEAD -> {team_lead.id}")
            else:
                user.team_lead = None

        # ==================================================
        # TEAM LEAD
        # ==================================================
        elif user.role == UserRole.TEAM_LEAD:

            logger.info("Processing TEAM_LEAD hierarchy assignment")

            if manager_id:
                manager = User.objects.get(id=manager_id, role=UserRole.MANAGER)
                user.manager = manager
                updated = True
                logger.info(f"Assigned MANAGER -> {manager.id}")
            else:
                user.manager = None

        # ==================================================
        # AGENT
        # ==================================================
        elif user.role == UserRole.AGENT:

            logger.info("Processing AGENT hierarchy assignment")

            if not manager_id or not team_lead_id:
                return {
                    "data": None,
                    "errors": {"details": "Agent requires both manager and team lead"},
                    "status": 400
                }

            manager = User.objects.get(id=manager_id, role=UserRole.MANAGER)
            team_lead = User.objects.get(id=team_lead_id, role=UserRole.TEAM_LEAD)

            user.manager = manager
            user.team_lead = team_lead

            updated = True

            logger.info(f"Assigned MANAGER -> {manager.id}")
            logger.info(f"Assigned TEAM_LEAD -> {team_lead.id}")

        # ==================================================
        # SAVE USER
        # ==================================================
        logger.info(
            f"BEFORE SAVE -> manager_id={user.manager_id}, team_lead_id={user.team_lead_id}, updated={updated}"
        )

        if updated:
            user.save()
        else:
            logger.warning("No hierarchy changes applied")

        # ==================================================
        # SYNC CLIENT PROFILE (if exists)
        # ==================================================
        try:
            client_profile = ClientProfile.objects.get(user=user)

            client_profile.manager = user.manager
            client_profile.team_lead = user.team_lead
            client_profile.save()

            logger.info(
                f"CLIENT PROFILE UPDATED -> manager_id={client_profile.manager_id}, "
                f"team_lead_id={client_profile.team_lead_id}"
            )

        except ClientProfile.DoesNotExist:
            logger.warning(f"ClientProfile not found for user_id={user.id}")

        # ==================================================
        # VERIFY DB STATE
        # ==================================================
        refreshed_user = User.objects.get(id=user.id)

        logger.info(
            f"AFTER SAVE (DB CHECK) -> manager_id={refreshed_user.manager_id}, "
            f"team_lead_id={refreshed_user.team_lead_id}"
        )

    return {
        "data": {"message": "Hierarchy assigned successfully"},
        "errors": None,
        "status": status.HTTP_200_OK
    }
