'use strict';
var CLIENT_ID = '70o3qickmokfvlk7sjib4bdm7l';
var USER_POOL_ID = 'us-east-1_fbOuIajds';
var AWS = require('aws-sdk');
AWS.config.update({region: 'us-east-1'});

module.exports.createUser = (event, context, callback) => {

  console.log("Event: " + JSON.stringify(event));
  var body = JSON.parse(event.body);
  var memberId = body.wrmemberid;
  console.log("Member: " + memberId);

  var username = body.username;
  var password = body.password;
  console.log("Starting createUser: " + username);

  var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider();
  
  //Check to see if the user exists in the User Pool using AdminGetUser()
  var params = {UserPoolId: USER_POOL_ID, Username: username};
  cognitoidentityserviceprovider.adminGetUser(params, function(lookup_err, data) {

      // User does not exist in the User Pool, try to migrate
      console.log("User does not exist in User Pool, attempting migration: " + username);
      console.log("Data back from adminCreateUser: " + JSON.stringify(data));

      //***********************************************************************
      // Attempt to sign in the user or verify the password with existing system
      // (shown in the next section of this article)
      //***********************************************************************

      //Create the user with AdminCreateUser()
        params = {
          UserPoolId: USER_POOL_ID,
          Username: username, 
          MessageAction: 'SUPPRESS', //suppress the sending of an invitation to the user
          TemporaryPassword: password,
          UserAttributes: [
            // {Name: 'name', Value: name}, 
            {Name: 'email', Value: username}, //using sign-in with email, so username is email
            {Name: 'email_verified', Value: 'true'}
            ]
        };
        cognitoidentityserviceprovider.adminCreateUser(params, function(err, data) {
          if (err) {
            console.log('Failed to Create migrating user in User Pool: ' + username);
            callback(err);
            return;               
          } else {
            //Successfully created the migrating user in the User Pool
            console.log("Successful AdminCreateUser for migrating user: " + username);
            console.log("Data back from successful user create: " + JSON.stringify(data));

            //Now sign in the migrated user to set the permanent password and confirm the user
            params = {
              AuthFlow: 'ADMIN_NO_SRP_AUTH',
              ClientId: CLIENT_ID,
              UserPoolId: USER_POOL_ID,
              AuthParameters: {USERNAME: username, PASSWORD: password}
            };

            cognitoidentityserviceprovider.adminInitiateAuth(params, function(signin_err, data) {
              if (signin_err) {
                console.log('Failed to sign in migrated user: ' + username);
                console.log(signin_err, signin_err.stack);
                callback(signin_err);
              } else {
                //Handle the response to set the password
                console.log("Handle Create User Success: " + data.sub + "|" + data.ChallengeName);
                //Confirm the challenge name is NEW_PASSWORD_REQUIRED
                if (data.ChallengeName !== "NEW_PASSWORD_REQUIRED") {
                  // unexpected challenge name - log and exit
                  console.log("Unexpected challenge name after adminInitiateAuth (" + data.ChallengeName + "), migrating user created, but password not set");
                 callback("Unexpected challenge name");
                }

                params = {
                  ChallengeName: "NEW_PASSWORD_REQUIRED",
                  ClientId: CLIENT_ID,
                  UserPoolId: USER_POOL_ID,
                  ChallengeResponses: {
                    'NEW_PASSWORD': password, 'USERNAME': data.ChallengeParameters.USER_ID_FOR_SRP
                  },
                  Session: data.Session
                };
                cognitoidentityserviceprovider.adminRespondToAuthChallenge(params, function(err, data) {
                  if (err) console.log(err, err.stack); // an error occurred
                  else {   // successful response
                    console.log('Successful response from RespondToAuthChallenge: ' + username);
                      const response = {
                        statusCode: 200,
                        body: JSON.stringify({
                          message: data,
                          input: event,
                        }),
                      };
                    callback(null, response);  
                    return;
                  }
                });
              }
            });         
          }
        }); 

  });   

};

module.exports.updateUser = (event, context, callback) => {

  console.log("Event: " + JSON.stringify(event));
  var body = JSON.parse(event.body);
  var username = body.username;
  var st = body.st;
  var expires_in = body.expires_in;
  var event_get_member_id = body.event_get_member_id;
  var get_UserLocalePref = body.get_UserLocalePref; 
  var get_encrptdmember_id = body.get_encrptdmember_id;
  var get_refresh_token = body.get_refresh_token;

  console.log("Starting updateUser: " + username);
  console.log("st: " + body.st);
  console.log("expires_in: " +  body.expires_in);
  console.log("event_get_member_id: " + body.event_get_member_id);
  console.log("get_UserLocalePref: " + body.get_UserLocalePref); 
  console.log("get_encrptdmember_id: " + body.get_encrptdmember_id);
  console.log("get_refresh_token: " + body.get_refresh_token);

  var cognitoidentityserviceprovider = new AWS.CognitoIdentityServiceProvider();

  var params =  {
    UserPoolId: USER_POOL_ID,
    Username: username,
    UserAttributes: [
    {Name: 'custom:st', Value: st}, 
    {Name: 'custom:expires_in', Value: expires_in},
    {Name: 'custom:event_get_member_id', Value: event_get_member_id}, 
    {Name: 'custom:get_UserLocalePref', Value: get_UserLocalePref}, 
    {Name: 'custom:get_encrptdmember_id', Value: get_encrptdmember_id}, 
    {Name: 'custom:get_refresh_token', Value: get_refresh_token}
    ]
  };

  cognitoidentityserviceprovider.adminUpdateUserAttributes(params, function(err, data) {
    if (err) {
      console.log('Failed to update attributes for: ' + username);
      console.log(err);
      callback(err);
    } else {   // successful response
      console.log('Successful response from RespondToAuthChallenge: ' + username);
      const response = {
        statusCode: 200,
        body: JSON.stringify({
          message: data,
          input: event,
        }),
      };
      callback(null, response);  // Tell client to retry sign-in
      return;
    }
  });

};



