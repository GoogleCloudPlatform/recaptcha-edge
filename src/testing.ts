import { Assessment, FirewallPolicy } from "./assessment";

export const policies: FirewallPolicy[] = [
    {
        name: "test-action-allow",
        description: "test-description",
        path: "/action/allow",
        actions: [{ allow: {} }],
    },
    {
        name: "test-action-block",
        description: "test-description",
        path: "/action/block",
        actions: [{ block: {} }],
    },
    {
        name: "test-action-redirect",
        description: "test-description",
        path: "/action/redirect",
        actions: [{ redirect: {} }],
    },
    {
        name: "condition-block-score-low",
        description: "test-description",
        path: "/condition/scorelow",
        condition: "recaptcha.score < 0.3",
        actions: [{ block: {} }],
    },
];

export const allow_policy = policies[0];
export const block_policy = policies[1];
export const redirect_policy = policies[2];


export const good_assessment: Assessment = {
    riskAnalysis: { score: 0.9 },
    firewallPolicyAssessment: {firewallPolicy: allow_policy}
}