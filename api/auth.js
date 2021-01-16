const request = require("request");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

const AmazonCognitoIdentity = require('amazon-cognito-identity-js');
const poolData = {
    UserPoolId: "us-west-2_7SAgpqeCf",
    ClientId: "5433s3rs1hp1h8jen8mnmk8s65",
};
const pool_region = "us-west-2";
const userPool = new AmazonCognitoIdentity.CognitoUserPool(poolData);
const register = (name, email, password, attributeList, callback) => {
    attributeList.push(new AmazonCognitoIdentity.CognitoUserAttribute({ Name: "email", Value: email }));
    userPool.signUp(name, password, attributeList, null,  (err, result) => {
        if (err) {
            callback(err);
        }
        callback(null, result.user);
    })
};

const login = (name, password, res) => {
    let authenticationDetails = new AmazonCognitoIdentity.AuthenticationDetails({
        Username: name,
        Password: password
    });
    let userData = {
        Username: name,
        Pool: userPool
    };
    let cognitoUser = new AmazonCognitoIdentity.CognitoUser(userData);
    cognitoUser.authenticateUser(authenticationDetails, {
        onFailure: function (err) {

        },
        onSuccess: function (result) {
            console.log("here");
            res.send(result.getAccessToken().getJwtToken());
        },
    })
};

const validate = (req, res, next) => {
    let token = req.headers.authorization;
    request({
        url : `https://cognito-idp.us-west-2.amazonaws.com/us-west-2_7SAgpqeCf/.well-known/jwks.json`,
        json : true
    }, (error, response, body) => {
        let pem;
        if (!error && response.statusCode === 200) {
            pems = {};
            let keys = body['keys'];
            for(let i = 0; i < keys.length; i++) {
                let key_id = keys[i].kid;
                let modulus = keys[i].n;
                let exponent = keys[i].e;
                let key_type = keys[i].kty;
                let jwk = { kty: key_type, n: modulus, e: exponent};
                pem = jwkToPem(jwk);
                pems[key_id] = pem;
            }
            let decodedJwt = jwt.decode(token, {complete: true});
            if (!decodedJwt) {
                console.log("Not a valid JWT token");
                res.status(401);
                return res.send("Invalid token");
            }
            let kid = decodedJwt.header.kid;
            pem = pems[kid];
            if (!pem) {
                console.log('Invalid token');
                res.status(401);
                return res.send("Invalid token");
            }
            jwt.verify(token, pem, function(err, payload) {
                if(err) {
                    console.log("Invalid Token.");
                    res.status(401);
                    return res.send("Invalid tokern");
                } else {
                    console.log("Valid Token.");
                    return next();
                }
            });
        } else {
            console.log("Error! Unable to download JWKs");
            res.status(500)
        }
    });
};

const simpleHello = (req, res) => {
    res.send("Hello from our node server");
};

module.exports = {
    login, register, validate, simpleHello
};