package com.tmobile.cloud.azurerules.policies;

import com.microsoft.azure.AzureClient;
import com.microsoft.azure.AzureServiceClient;
import com.microsoft.azure.management.Azure;
import com.tmobile.cloud.awsrules.utils.PacmanUtils;
import com.tmobile.cloud.constants.PacmanRuleConstants;
import com.tmobile.pacman.commons.AWSService;
import com.tmobile.pacman.commons.PacmanSdkConstants;
import com.tmobile.pacman.commons.azure.clients.AzureCredentialManager;
import com.tmobile.pacman.commons.rule.Annotation;
import com.tmobile.pacman.commons.rule.BaseRule;
import com.tmobile.pacman.commons.rule.RuleResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.util.Map;

public class AzureLogAndMonitorEvaluation extends BaseRule {

	private static final Logger logger = LoggerFactory.getLogger(AzurePolicyEvaluationRule.class);

	@Override
	public RuleResult execute(Map<String, String> ruleParam, Map<String, String> resourceAttributes) {

		logger.debug("======== Azure Policy Evaluation Rule started =========");

		MDC.put("executionId", ruleParam.get("executionId"));
		MDC.put("ruleId", ruleParam.get(PacmanSdkConstants.RULE_ID));

		String severity = ruleParam.get(PacmanRuleConstants.SEVERITY);
		String category = ruleParam.get(PacmanRuleConstants.CATEGORY);

		String resourceId = resourceAttributes.get(PacmanRuleConstants.RESOURCE_ID).toLowerCase();
		String pacmanHost = PacmanUtils.getPacmanHost(PacmanRuleConstants.ES_URI);

		Annotation annotation = Annotation.buildAnnotation(ruleParam, Annotation.Type.ISSUE);
		annotation.put(PacmanRuleConstants.SEVERITY, severity);
		annotation.put(PacmanRuleConstants.CATEGORY, category);
		annotation.put(PacmanRuleConstants.AZURE_SUBSCRIPTION, resourceAttributes.get(PacmanRuleConstants.AZURE_SUBSCRIPTION));
		annotation.put(PacmanRuleConstants.AZURE_SUBSCRIPTION_NAME, resourceAttributes.get(PacmanRuleConstants.AZURE_SUBSCRIPTION_NAME));

		Azure client = AzureCredentialManager.authenticate(resourceAttributes.get(PacmanRuleConstants.AZURE_SUBSCRIPTION));


		return null;
	}

	@Override
	public String getHelpText() {
		return null;
	}
}
