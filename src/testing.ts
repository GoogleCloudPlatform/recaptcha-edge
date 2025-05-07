import { Assessment } from "./assessment";

export const policies = [
    {
        name: "test-action-allow",
        description: "test-description",
        path: "/action/allow",
        // 'type' isn't a part of the interface, but is added for testing.
        actions: [{ allow: {}, type: "allow" }],
    },
    {
        name: "test-action-block",
        description: "test-description",
        path: "/action/block",
        actions: [{ block: {}, type: "block" }],
    },
    {
        name: "test-action-redirect",
        description: "test-description",
        path: "/action/redirect",
        actions: [{ redirect: {}, type: "redirect" }],
    },
    {
        name: "condition-block-score-low",
        description: "test-description",
        path: "/condition/scorelow",
        condition: "recaptcha.score < 0.3",
        actions: [{ block: {}, type: "block" }],
    },
];

export const allow_policy = policies[0];
export const block_policy = policies[1];
export const redirect_policy = policies[2];


export const good_assessment: Assessment = {
    riskAnalysis: { score: 0.9 },
    firewallPolicyAssessment: {firewallPolicy: allow_policy}
}