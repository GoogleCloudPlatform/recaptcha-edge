import { evaluate, parse } from "cel-js";
import { UserInfo, UserInfoSchema } from "./assessment";

// Sample User Info Config (Fieldname should be provided by clients; probably stored in WAF first)
// Syntax should be: user_info_account_id: <cel_expr>
const userInfoConfig: {
  [key: string]: string; // Index signature
  accountId: string;
  userIds: string;
} = {
  accountId: "has(accountIdField)",
  userIds: `[{email: user.emailField, phoneNumber: user.phoneNumberField, username: user.usernameField}]`,
};

// Example userinfo from an incoming POST request body
const target_user: { [key: string]: string } = {
  accountIdField: "testuser",
  emailField: "test@example.com",
  phoneNumberField: "123-456-7890",
  usernameField: "abcdef",
};

// Evaluate the user information against the configuration
let userInfo: UserInfo = { accountId: "", userIds: [] };
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
      if (key === "accountId") {
        // Extract field name
        const fieldName = expression.split("(")[1].split(")")[0];
        userInfo.accountId = target_user[fieldName];
      }
      if (key === "userIds") {
        const userIdsResult = evaluate(expression, {
          target_user: target_user,
        });
        // Type assertion for userIdsResult
        userInfo.userIds = userIdsResult as UserInfo["userIds"];
      }
      // Validate the final userInfo against the schema
      const parsedUserInfo = UserInfoSchema.safeParse(userInfo);
      if (parsedUserInfo.success) {
        console.log("UserInfo is valid:", parsedUserInfo.data);
      } else {
        console.error("UserInfo is invalid:", parsedUserInfo.error);
      }
    } else {
      console.error("Field not found in user data");
    }
  } catch (error) {
    console.error(`Error evaluating CEL expression for ${key}:`, error);
  }
}
