package com.tmobile.cloud.awsrules.iam;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import com.amazonaws.services.identitymanagement.model.*;
import com.amazonaws.services.s3.AmazonS3Client;
import com.tmobile.cloud.awsrules.utils.PacmanUtils;
import com.tmobile.cloud.constants.PacmanRuleConstants;
import com.tmobile.pacman.commons.AWSService;
import com.tmobile.pacman.commons.PacmanSdkConstants;
import com.tmobile.pacman.commons.exception.InvalidInputException;
import com.tmobile.pacman.commons.rule.Annotation;
import com.tmobile.pacman.commons.rule.BaseRule;
import com.tmobile.pacman.commons.rule.PacmanRule;
import com.tmobile.pacman.commons.rule.RuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.tmobile.cloud.constants.PacmanRuleConstants.USER_NAME;


@PacmanRule(key = "check-if-MFA-enabled-for-global-account-admins", desc = "Check whether MFA is enabled for Global/ Account Level Administrators.", severity = PacmanSdkConstants.SEV_HIGH, category = PacmanSdkConstants.SECURITY)
public class CheckAdminMFAEnabled extends BaseRule {

	String admin_access = "AdministratorAccess";

	public static final Logger logger = LoggerFactory.getLogger(CheckAdminMFAEnabled.class);

	@Override
	public RuleResult execute(Map<String, String> ruleParam, Map<String, String> resourceAttributes) {
		logger.debug("======== Global Admin MFA Account Check Started =========");

		Map<String, String> ruleParamIam = new HashMap<>();
		ruleParamIam.putAll(ruleParam);
		ruleParamIam.put(PacmanSdkConstants.REGION, Regions.DEFAULT_REGION.getName());

		Map<String, Object> map = null;
		Annotation annotation = null;
		AmazonIdentityManagementClient identityManagementClient = null;
		String roleIdentifyingString = ruleParam.get(PacmanSdkConstants.Role_IDENTIFYING_STRING);
		String userName = resourceAttributes.get(USER_NAME);
		String unapprovedActionsParam = ruleParam.get(PacmanRuleConstants.UNAPPROVED_IAM_ACTIONS);
		String tagsSplitter = ruleParam.get(PacmanSdkConstants.SPLITTER_CHAR);

		String severity = ruleParam.get(PacmanRuleConstants.SEVERITY);
		String category = ruleParam.get(PacmanRuleConstants.CATEGORY);

		MDC.put(PacmanSdkConstants.EXECUTION_ID, ruleParam.get(PacmanSdkConstants.EXECUTION_ID));
		MDC.put(PacmanSdkConstants.RULE_ID, ruleParam.get(PacmanSdkConstants.RULE_ID));


		try {
			map = getClientFor(AWSService.IAM, roleIdentifyingString, ruleParamIam);
			identityManagementClient = (AmazonIdentityManagementClient) map.get(PacmanSdkConstants.CLIENT);
		} catch (Exception e) {
			logger.error(PacmanRuleConstants.UNABLE_TO_GET_CLIENT, e);
			throw new InvalidInputException(PacmanRuleConstants.UNABLE_TO_GET_CLIENT, e);
		}


		List<UserDetail> userDetails = identityManagementClient.getAccountAuthorizationDetails().getUserDetailList();
		List<UserDetail> adminUsers = new ArrayList<>();

		for (UserDetail userDetail : userDetails)
			if (isUserAdmin(userDetail, identityManagementClient))
				adminUsers.add(userDetail);

		for(UserDetail admin : adminUsers)
			if (identityManagementClient.listMFADevices(
					new ListMFADevicesRequest().withUserName(admin.getUserName()))
				.getMFADevices().isEmpty())
				return
						new RuleResult(PacmanSdkConstants.STATUS_FAILURE, PacmanRuleConstants.FAILURE_MESSAGE);


		return new RuleResult(PacmanSdkConstants.STATUS_SUCCESS, PacmanRuleConstants.SUCCESS_MESSAGE);
	}


	public boolean isUserAdmin(UserDetail user, AmazonIdentityManagementClient client) {
		return userHasAdminFromGroup(user, client) || userHasAdminOrAttachedPolicy(user);
	}


	public boolean userHasAdminOrAttachedPolicy(UserDetail user) {

		for (PolicyDetail policy : user.getUserPolicyList())
			if (policy.equals(admin_access))
				return true;

		for (AttachedPolicy attachedPolicy : user.getAttachedManagedPolicies())
			if (attachedPolicy.equals(admin_access))
				return true;

		return false;
	}

	public boolean userHasAdminFromGroup(UserDetail user, AmazonIdentityManagementClient client) {
		List<String> userGroupList = user.getGroupList();

		for (String group : userGroupList) {
			for (String policy : client.listGroupPolicies(
					new ListGroupPoliciesRequest().withGroupName(group)).getPolicyNames())
				if (policy.equals(admin_access))
					return true;

			for (AttachedPolicy attachedPolicy : client.listAttachedGroupPolicies(
					new ListAttachedGroupPoliciesRequest().withGroupName(group)).
					getAttachedPolicies())
				if (attachedPolicy.equals(admin_access))
					return true;
		}

		return false;
	}


	@Override
	public String getHelpText() {
		return null;
	}


}
