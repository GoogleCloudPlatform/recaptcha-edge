import { evaluate, parse } from "cel-js";
import { z } from "zod";

// UserInfo used in Assessment
const UserInfoSchema = z.object({
  accountId: z.string().optional(),
  userIds: z
    .array(
      z.object({
        email: z.string().optional(),
        phoneNumber: z.string().optional(),
        username: z.string().optional(),
      }),
    )
    .optional(),
});

type UserInfo = z.infer<typeof UserInfoSchema>;

// Sample User Info Config (provided by clients; probably stored in WAF first)
// Format should be: user_info_account_id: <cel_expr>
const userInfoConfig: {
  [key: string]: string; // Index signature
  accountId: string;
  email: string;
  phoneNumber: string;
} = {
  accountId: "has(accountIdField)",
  email: "has(emailField)",
  phoneNumber: "has(phoneNumberField)",
};

// Example userinfo from an incoming POST request
const target_user: { [key: string]: string } = {
  accountIdField: "testuser",
  emailField: "test@example.com",
  phoneNumberField: "123-456-7890",
};

// Evaluate the user information against the configuration
for (const key in userInfoConfig) {
  const expression = userInfoConfig[key];
  try {
    const parsedExpression = parse(expression);
    if (!parsedExpression.isSuccess) {
      console.error(`Invalid CEL expression for ${key}:`, parsedExpression.errors);
      continue;
    }
    // Evaluate if target_user matches the field.
    const result = evaluate(parsedExpression.cst, { user: target_user });

    // Check if the field exists based on the CEL evaluation
    if (result === true) {
      // Extract field name
      const fieldName = expression.split("(")[1].split(")")[0];
      // Assign the value of target_user[fieldName] in getUserInfo before CreateAssessment
      // Something like:
      let userInfo: UserInfo = { accountId: "", userIds: [] };
      userInfo = target_user[fieldName];
    } else {
      console.error("Field not found in user data");
    }
  } catch (error) {
    console.error(`Error evaluating CEL expression for ${key}:`, error);
  }
}
