require("./utils.js");
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const url = require("url");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 1 * 60 * 60 * 1000; // 1 hour expiration

// secret info
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const saltRounds = 12;

var {database} = include("databaseConnection");
const userCollection = database.db(mongodb_database).collection("users");

const navLinks = [
    {name: "Home", link: "/"},
    {name: "Cats", link: "/cats"},
    {name: "Login", link: "/login"},
    {name: "Admin", link: "/admin"},
    {name: "404", link: "/dne"},
]

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
    store: mongoStore, // memory store is the default value
    saveUninitialized: false, 
    resave: true
}));

// middleware functions
function sessionValidation(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect("/login");
    }
}

function adminAuthorization(req, res, next) {
    if (req.session.userType == "admin") {
        next();
    } else {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
}

app.use("/", (req, res, next) => {
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
});

app.get("/", async (req, res) => {
    res.render("index", {authenticated: req.session.authenticated, name: req.session.name});
});

app.get("/nosql-injection", async (req, res) => {
	var email = req.query.email;

	if (!email) {
		res.render("errorMessage", {error: "No email provided - try /nosql-injection?user=email or /nosql-injection?user[$ne]=email"});
		return;
	}
	console.log("email: " + email);
	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.render("errorMessage", {error: "A NoSQL injection attack was detected!!"});
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, name: 1, userType: 1, password: 1, _id: 1}).toArray();
	console.log(result);

    res.redirect("/cats");
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.get("/login", (req, res) => {
    res.render("login");
});

// create account
app.post("/submitUser", async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    // send back to sign up page if any field is empty
    var emptyField;
    if (name == "") {
        emptyField = "Name";
    } else if (email == "") {
        emptyField = "Email";
    } else if (password == "") {
        emptyField = "Password";
    }

    if (emptyField != null) {
        res.send(`
        ${emptyField} is required.
        <br/><br/>
        <a href="/signup">Try again</a>
        `)
    }

	const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().max(20).required(),
        password: Joi.string().max(20).required()
	});
	
	const validationResult = schema.validate({email, name, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/signup");
	   return;
    }
    
    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({email: email, name: name, userType: "user", password: hashedPassword});
	console.log("Inserted user");

    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = name;
    req.session.userType = "user";
    req.session.cookie.maxAge = expireTime;

    res.redirect("/cats");
});

app.post("/loggingin", async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, name: 1, userType: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.send(`
        User not found.<br/>
        <br/>
        <a href="/login">Try again</a>
        `)
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = result[0].email;
		req.session.name = result[0].name;
        req.session.userType = result[0].userType;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/cats');
		return;
	} else {
		console.log("incorrect password");
		res.send(`
        Invalid password.<br/>
        <br/>
        <a href="/login">Try again</a>
        `)
		return;
	}
});

app.get("/cats", sessionValidation, (req, res) => {
    res.render("cats");
});

app.get("/logout", (req, res) => {
	req.session.destroy();
    res.redirect("/");
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({email: 1, name: 1, userType: 1, _id: 1}).toArray();
    res.render("admin", {users: result});
});

app.get("/promoteUser", adminAuthorization, (req, res) => {
    userCollection.updateOne({email: req.query.email}, {$set: {userType: "admin"}});
    res.redirect("/admin");
});

app.get("/demoteUser", adminAuthorization, (req, res) => {
    userCollection.updateOne({email: req.query.email}, {$set: {userType: "user"}});
    res.redirect("/admin");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port " + port);
}); 
