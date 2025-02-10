import { evaluate, parse } from "cel-js";

function lookup_json_string(obj: { [x: string]: any; hasOwnProperty: (arg0: any) => any }, key: string | number) {
  if (obj && typeof obj === "object" && obj.hasOwnProperty(key)) {
    return obj[key];
  }
  return "";
}

const bindings = {
  // variable: 'lookup_json_string(fieid, target_name)' which are from the environment variables
  expected_action: 'lookup_json_string(http.request.body.form, "expected_action")',
  user_info_account_id: 'lookup_json_string(http.request.body.form, "account_id")',
  user_info_password: 'lookup_json_string(http.request.body.form, "password")',
  user_info_phone: 'lookup_json_string(http.request.body.form, "phone")',
  user_info_email: 'lookup_json_string(http.request.body.form, "email")',
};

// Example Request
const sampleRequest = {
  body: {
    form: {
      expected_action: "login",
      account_id: "12345",
      password: "secret",
      phone: "123-456-7890",
      email: "test@example.com",
    },
    multipart: {
      /* ... */
    },
    raw: '{ "key": "value" }', // Handle raw data parsing as needed
  },
  headers: {
    /* ... */
  },
  uri: {
    query: {
      /* ... */
    },
  },
};

const context = { http: { request: sampleRequest } };

// Evaluate the bindings
const evaluatedBindings = {};
for (const key in bindings) {
  try {
    const parsedExpression = parse(bindings[key]);
    if (!parsedExpression.isSuccess) {
      console.error(`Invalid CEL expression for ${key}:`, parsedExpression.errors);
      // Handle the error appropriately, maybe skip this binding
      continue;
    }
    evaluatedBindings[key] = evaluate(parsedExpression.cst, context, { lookup_json_string });
  } catch (error) {
    console.error(`Error evaluating CEL expression for ${key}:`, error);
    // Handle the error appropriately
    continue;
  }
}

console.log(evaluatedBindings);

// Example of accessing a bound value:
console.log(evaluatedBindings.expected_action); // Output: login

// Example of looking up in a different field:
const bindings2 = {
  user_info_email: 'lookup_json_string(http.request.headers, "X-User-Email")',
};

const context2 = { http: { request: sampleRequest } };
const evaluatedBindings2 = {};

for (const key in bindings2) {
  try {
    const parsedExpression = parse(bindings2[key]);
    if (!parsedExpression.isSuccess) {
      console.error(`Invalid CEL expression for ${key}:`, parsedExpression.errors);
      // Handle the error appropriately, maybe skip this binding
      continue;
    }
    evaluatedBindings2[key] = evaluate(parsedExpression.cst, context2, { lookup_json_string });
  } catch (error) {
    console.error(`Error evaluating CEL expression for ${key}:`, error);
    // Handle the error appropriately
    continue;
  }
}

console.log(evaluatedBindings2); // will log user_info_email as undefined, since X-User-Email is not in sampleRequest.headers
