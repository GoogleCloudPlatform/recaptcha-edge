import { Assessment, FirewallPolicy } from "./assessment";

export const policies: FirewallPolicy[] = [
    {
        name: "projects/12345/firewallpolicies/100",
        description: "test-action-allow",
        path: "/action/allow",
        actions: [{ allow: {} }],
    },
    {
        name: "projects/12345/firewallpolicies/200",
        description: "test-action-block",
        path: "/action/block",
        actions: [{ block: {} }],
    },
    {
        name: "projects/12345/firewallpolicies/300",
        description: "test-action-redirect",
        path: "/action/redirect",
        actions: [{ redirect: {} }],
    },
    {
        name: "projects/12345/firewallpolicies/400",
        description: "condition-allow-score-high",
        path: "/condition/allowifscorehigh",
        condition: "recaptcha.score > 0.5",
        actions: [{ block: {} }],
    },
    {
        name: "projects/12345/firewallpolicies/500",
        description: "condition-block-score-low",
        path: "/condition/blockifscorelow",
        condition: "recaptcha.score < 0.3",
        actions: [{ block: {} }],
    },
];

export const allow_policy = policies[0];
export const block_policy = policies[1];
export const conditional_block_policy = policies[4];
export const redirect_policy = policies[2];


export const good_assessment: Assessment = {
    riskAnalysis: { score: 0.9 },
    firewallPolicyAssessment: {firewallPolicy: allow_policy}
}

export const bad_assessment: Assessment = {
    name: "projects/12345/assessments/1234567890",
    riskAnalysis: { score: 0.1 },
    firewallPolicyAssessment: {firewallPolicy: conditional_block_policy}
}