import jwt from 'jsonwebtoken'
// By default, API Gateway authorizations are cached (TTL) for 300 seconds.
// This policy will authorize all requests to the same API Gateway instance where the
// request is coming from, thus being efficient and optimising costs.

// This function purelly, creates a policy to authorize the execution of lambda functions.
// The principal id is the id of the user, gived by Auth0
const generatePolicy = (principalId, methodArn) => {
    // The methodArn is an string commonly added by API Gateway to lambda function which are used
    // as authorizer for a API Gateway endpoint.
    // This wildcard allows the execution of any lambda function in the target API Gateway
    const apiGatewayWildcard = methodArn.split('/', 2).join('/') + "/*"
    // Here's an example of what a methodArn looks like
    // arn:aws:execute-api:region:account-id:api-id/stage/method/resource 
    // Where:
    // region is the AWS region (e.g., us-east-1).
    // account-id is the AWS account ID.
    // api-id is the API Gateway's ID.
    // stage is the deployment stage (e.g., dev, prod).
    // method is the HTTP method (e.g., GET, POST).
    // resource is the API resource path (e.g., /users).
    // This methodArn is important in authorizer Lambda functions because you
    // typically return an IAM policy that controls access to specific API Gateway
    // methods based on the value of methodArn.

    return {
        principalId,
        policyDocument: {
            Version: '2012-10-17',
            Statement: [
                {
                    Action: 'execute-api:Invoke',
                    Effect: 'Allow',
                    Resource: apiGatewayWildcard
                }
            ]
        }
    }
}

// When a user sends a request to a protected resource, which have an authorizer lambda function
// what happens is that API Gateway sends a request to this function which works as an authorizer
// This function should return an AWS policy to the API Gateway to have access to decide if it will process
// The request or not.
export async function handler(event, context) {
    if (!event.authorizationToken) {
        throw 'Unauthorized'
    }

    const token = event.authorizationToken.replace('Bearer ', '')

    try {
        // Is the JWT is valid, then the verify method returns the object.
        const claims = jwt.verify(token, process.env.AUTH0_PUBLIC_KEY)

        console.log(claims)

        // Here we generate the policy
        const policy = generatePolicy(claims.sub, event.methodArn)

        // Here we return the policy, and in the object key the claims (the JWT decrypted object)
        return {
            ...policy,
            // This is our opportunity to give any information which can be useful for us.
            context: {
                ...claims
            }
        }
    } catch (err) {
        console.log(err)
        throw 'Unauthorized'
    }
}