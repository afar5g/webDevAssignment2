require("./utils.js");
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcrypt");

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const expireTime = 24 * 60 * 60 * 1000; // 1 day expiration

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

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(
    session({ 
        secret: node_session_secret,
        store: mongoStore, // memory store is the default value
        saveUninitialized: false, 
        resave: true
    }
));

app.get('/', async (req, res) => {
    if (!req.session.authenticated) {
        res.send(`
        <button onclick="location.href='/signup';">Sign up</button>
        <button onclick="location.href='/login';">Log in</button>
        `);
    } else {
        const name = req.session.name;
        res.send(`
        Hello, ${name}!<br/>
        <button onclick="location.href='/members';">Go to Members Area</button>
        <button onclick="location.href='/logout';">Logout</button>
        `);
    }
});

app.get('/nosql-injection', async (req, res) => {
	var email = req.query.email;

	if (!email) {
		res.send(`<h3>no email provided - try /nosql-injection?user=email</h3> <h3>or /nosql-injection?user[$ne]=email</h3>`);
		return;
	}
	console.log("email: " + email);
	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({email: email}).project({email: 1, name: 1, password: 1, _id: 1}).toArray();
	console.log(result);
});

app.get('/about', (req, res) => {
    var color = req.query.color;
    res.send("<h1 style='color:" + color + ";'>Ali Farahani</h1>");
});

app.get('/signup', (req, res) => {
    res.send(`
    Sign Up:
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'><br/>
    <input name='email' type='email' placeholder='email'><br/>
    <input name='password' type='password' placeholder='password'><br/>
    <br/>
    <button>Submit</button>
    </form>
    `);
});

app.get('/login', (req, res) => {
    res.send(`
    Log In:
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `);
});

// create account
app.post('/submitUser', async (req, res) => {
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
	
	await userCollection.insertOne({email: email, name: name, password: hashedPassword});
	console.log("Inserted user");

    req.session.authenticated = true;
    req.session.email = email;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, name: 1, password: 1, _id: 1}).toArray();

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
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	} else {
		console.log("incorrect password");
		res.send(`
        Invalid email/password combination.<br/>
        <br/>
        <a href="/login">Try again</a>
        `)
		return;
	}
});

app.get('/members', (req, res) => {
    if (req.session.authenticated) {
        let randNum = Math.floor(Math.random() * 3); // random num from 0 to 2
        let images = ["fluffy.gif", "socks.gif", "marble.jpeg"];
        let randImg = images[randNum];

        res.send(`
        <h1>Hello, ${req.session.name}.</h1><br/>
        <img src="/${randImg}" alt="">
        <button onclick="location.href='/logout';">Sign out</button>
        `)
    } else {
        res.redirect("/");
    }
});

app.get('/logout', (req, res) => {
	req.session.destroy();
    res.redirect("/");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port " + port);
}); 
