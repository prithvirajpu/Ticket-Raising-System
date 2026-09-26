/**
 * Validates salary distribution rules and returns field-specific inline errors.
 */
export const validateSalaryConfig = (form) => {
  const errors = {};

  // Parse values to float or null if empty
  const agent = form.agent_percentage !== "" && form.agent_percentage !== null ? parseFloat(form.agent_percentage) : NaN;
  const incentive = form.incentive_percentage !== "" && form.incentive_percentage !== null ? parseFloat(form.incentive_percentage) : NaN;
  const teamLead = form.team_lead_percentage !== "" && form.team_lead_percentage !== null ? parseFloat(form.team_lead_percentage) : NaN;
  const manager = form.manager_percentage !== "" && form.manager_percentage !== null ? parseFloat(form.manager_percentage) : NaN;

  // =========================
  // Agent Validation (10% to 50%)
  // =========================
  if (form.agent_percentage === "" || form.agent_percentage === null || form.agent_percentage === undefined) {
    errors.agent_percentage = "Agent percentage is required";
  } else if (isNaN(agent)) {
    errors.agent_percentage = "Agent percentage must be a valid number";
  } else if (agent < 10 || agent > 50) {
    errors.agent_percentage = "Agent percentage must be between 10% and 50%";
  }

  // =========================
  // Incentive Validation (Under 8%)
  // =========================
  if (form.incentive_percentage === "" || form.incentive_percentage === null || form.incentive_percentage === undefined) {
    errors.incentive_percentage = "Incentive percentage is required";
  } else if (isNaN(incentive)) {
    errors.incentive_percentage = "Incentive percentage must be a valid number";
  } else if (incentive < 0) {
    errors.incentive_percentage = "Incentive percentage cannot be negative";
  } else if (incentive >= 8) {
    errors.incentive_percentage = "Incentive percentage must be under 8%";
  }

  // =========================
  // Team Lead Validation (Within 15%)
  // =========================
  if (form.team_lead_percentage === "" || form.team_lead_percentage === null || form.team_lead_percentage === undefined) {
    errors.team_lead_percentage = "Team Lead percentage is required";
  } else if (isNaN(teamLead)) {
    errors.team_lead_percentage = "Team Lead percentage must be a valid number";
  } else if (teamLead < 0 || teamLead > 15) {
    errors.team_lead_percentage = "Team Lead percentage must be within 15%";
  }

  // =========================
  // Manager Validation (Within 10%)
  // =========================
  if (form.manager_percentage === "" || form.manager_percentage === null || form.manager_percentage === undefined) {
    errors.manager_percentage = "Manager percentage is required";
  } else if (isNaN(manager)) {
    errors.manager_percentage = "Manager percentage must be a valid number";
  } else if (manager < 0 || manager > 10) {
    errors.manager_percentage = "Manager percentage must be within 10%";
  }

  // =========================
  // Total Allocation Validation (Max 100%)
  // =========================
  if (!Object.keys(errors).length) {
    const total = agent + incentive + teamLead + manager;
    if (total > 100) {
      errors.total = "Total distribution cannot exceed 100%";
    }
  }

  return {
    isValid: Object.keys(errors).length === 0,
    errors,
  };
};