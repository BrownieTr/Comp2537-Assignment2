/* Set up */
require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const port = process.env.PORT || 3000;
const app = express();
const Joi = require("joi");


const expireTime = 60 * 60 * 1000; //expires after 1 hour (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

/* END secret section */

const {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));
app.set('view engine', 'ejs');

const mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({ 
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false, 
    resave: true
}
))

function createSession(req, username, type) {
    req.session.authenticated = true;
    req.session.username = username;
    req.session.usertype = type;
    req.session.cookie.maxAge = expireTime;
}

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.usertype == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("403");
        return;
    }
    else {
        next();
    }
}

app.get('/', (req, res) => {
    res.render("index", {user: req.session.username});
})

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
})

app.get('/signup', (req, res) => {
    res.render("signup");
})

app.post('/signupSubmit', async (req, res) => {
    const username = req.body.name;
    const email = req.body.email;
    const password = req.body.password;
    const signup = "signup";

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().max(254).required(),
            password: Joi.string().max(20).required()
        });
    
    const validationResult = schema.validate({username, email, password});
    if (validationResult.error != null) {
       console.log(validationResult.error);
       res.render("error", {validateResult: validationResult, type: signup});
       return;
    }

    const userExisted = await userCollection.find().toArray();
    const userFound = await userCollection.find({email: email}).toArray();
    console.log(userFound)

    if (userFound.length != 1) {
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        if (userExisted.length != 0) {
            await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: "user"});
            createSession(req, username, "user");
        } else {
            await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: "admin"});
            createSession(req, username, "admin");
        }
        console.log("Inserted user");

        res.redirect("/members");
        return;
    } else {
        console.log("Email already signed up");
        res.render("error", {user: userFound, type: signup});
		return;
    }
})

app.get('/login', (req, res) => {
    res.render("login");
})

app.post('/loginSubmit', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password;
    const login = "login";

    const schema = Joi.object(
        {
            email: Joi.string().email().max(254).required(),
            password: Joi.string().max(20).required()
        });
    
    const validationResult = schema.validate({email, password});
    if (validationResult.error != null) {
       console.log(validationResult.error);
       res.render("error", {validateResult: validationResult, type: login});
       return;
    }

    const userFound = await userCollection.find({email: email}).project({username: 1, password: 1, user_type: 1}).toArray();
    console.log(userFound)

    if (userFound.length != 1) {
        console.log("User not found");
        res.render("error", {user: userFound, type: login});
        return;
    }       
    
    if (await bcrypt.compare(password, userFound[0].password)) {
        console.log("Correct password");
        createSession(req, userFound[0].username, userFound[0].user_type)

        res.redirect('/members');
        return;
    } else {
		console.log("incorrect password");
        res.render("error", {password: password});
		return;
    }
})

app.get('/members', (req, res) => {
    if (req.session.authenticated) {
        const randomNum = Math.floor(Math.random() * 3);
        res.render("members", {randomNum: randomNum, user: req.session.username});
        return;
    } else {
        res.redirect('/');
        return;
    }
})

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const collection = await userCollection.find().project({username: 1, email: 1, user_type: 1}).toArray();
            
    res.render("admin", {users: collection});
})

app.get('/promote', async (req, res) => {
    const type = req.query.type;
    const email = req.query.email;
    if (type) {
        await userCollection.updateOne({email: email}, {$set: {user_type: type}});
        res.redirect("/admin");
        return;
    } else {
        res.redirect("/login");
        return;
    }
})

app.use(express.static(__dirname + "/public"))

app.get("*", (req, res) => {
    res.status(404);
    res.render("404.ejs")
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
})

