const api = require('./api/api');
const AWS = require('aws-sdk');
const AWSCognito = require('amazon-cognito-identity-js');
const express  = require('express');
const bodyParser = require('body-parser');

api.auth.login(1, 2);

let app = express();
app.use(bodyParser.json());       // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({     // to support URL-encoded bodies
    extended: true
}));
app.use('/static', express.static(__dirname + '/static'));

app.get("/", (req, res) => {
    res.sendFile('/static/views/index.html', {root: __dirname })
});


app.post("/register", (req, res) => {
    let name = req.body.name;
    let email = req.body.email;
    let password = req.body.password;
    let attributeList = [];
    api.auth.register(name, email, password, attributeList, (err, result) => {
        if (err)
            res.send(err);
        res.send(result);
    })
    }
);

app.post("/login", (req, res) => {
        let name = req.body.name;
        let password = req.body.password;
        return api.auth.login(name, password, res)
    }
);

app.post("/hello", api.auth.validate, api.auth.simpleHello);

app.listen(80);