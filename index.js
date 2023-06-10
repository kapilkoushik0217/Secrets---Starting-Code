require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
	secret: process.env.SECRET,
	resave: false,
	saveUninitialized: true,
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.DATABASE_URL, {
	useNewUrlParser: true,
	useUnifiedTopology: true
}).then(() => console.log("Database connected"))
.catch(err => console.log(err));

const userSchema = new mongoose.Schema({
	username: String,
	password: String,
	displayName: String,
	secret: String
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
	process.nextTick(function() {
		done(null, { id: user._id, username: user.username });
	});
});
passport.deserializeUser(function(user, done) {
	process.nextTick(function() {
		return done(null, user);
	});
});

///////////////// USE STRATEGIES /////////////////

passport.use(new GoogleStrategy({
	clientID: process.env.CLIENT_ID,
	clientSecret: process.env.CLIENT_SECRET,
	callbackURL: "http://localhost:3000/auth/google/secrets",
	},
	async function (accessToken, refreshToken, profile, done) {
		try {
			let user = await User.findOne({ username: profile.id });
			if (!user) {
				// Next line is in case I ever want to connect Google and Facebook users through email
				//const username = Array.isArray(profile.emails) && profile.emails.length > 0 ? profile.emails[0].value.split('@')[0] : '';
				const newUser = new User({
					username: profile.id,
					displayName: profile.displayName
				});
				user = await newUser.save();
			}
			return done(null, user);
		} catch (err) {
			return done(err);
		}
	}
));

passport.use(new FacebookStrategy({
	clientID: process.env.FACEBOOK_ID,
	clientSecret: process.env.FACEBOOK_SECRET,
	callbackURL: "http://localhost:3000/auth/facebook/secrets",
	},
	async function (accessToken, refreshToken, profile, done) {
		try {
			console.log(profile);
			let user = await User.findOne({ username: profile.id });
			if (!user) {
				const newUser = new User({
					username: profile.id,
					displayName: profile.displayName
				});
				user = await newUser.save();
			}
			return done(null, user);
		} catch (err) {
			return done(err);
		}
	}
));

///////////////// GET ROUTES /////////////////

app.get("/", function(req, res) {
	res.render("home");
});

app.get("/auth/google",
	passport.authenticate("google", { scope: ["profile"] })
);

app.get("/auth/google/secrets",
	passport.authenticate("google", { failureRedirect: "/login" }),
	function(req, res) {
		res.redirect("/secrets");
	}
);

app.get("/auth/facebook",
	passport.authenticate("facebook")
);

app.get("/auth/facebook/secrets",
	passport.authenticate("facebook", { failureRedirect: "/login" }),
	function(req, res) {
		res.redirect("/secrets");
	}
);

app.get("/login", function(req, res) {
	res.render("login");
});

app.get("/register", function(req, res) {
	res.render("register");
});

app.get("/secrets", function(req, res) {
	User.find({secret: {$ne: null}})
	.then((foundUsers) => {
    console.log(foundUsers);
		res.render("secrets", {usersWithSecrets: foundUsers})
	})
	.catch((err) => {
		console.log(err);
	});
});

app.get("/logout", (req, res, next) => {
	req.logout(function(err) {
		if (err) {
			return next(err);
		}
		res.redirect('/');
	});
});

app.get("/submit", function(req, res) {
	if (req.isAuthenticated()) {
		res.render("submit");
	} else {
		res.redirect("/login");
	}
});

///////////////// POST ROUTES /////////////////

app.post("/register", async (req, res) => {
	try {
		const registerUser = await User.register({username: req.body.username}, req.body.password);
		if (registerUser) {
			passport.authenticate("local") (req, res, function() {
				res.redirect("/secrets");
			});
		} else {
			res.redirect("/register");
		}
	} catch (err) {
		res.send(err);
	}
});

app.post("/login", (req, res) => {
	const user = new User({
		username: req.body.username,
		password: req.body.password
	});

	req.login(user, (err) => {
		if (err) {
			console.log(err);
		} else {
			passport.authenticate("local")(req, res, function() {
				res.redirect("/secrets");
			});
		}
	});
});

app.post("/submit", function(req, res) {
	const submittedsecret = req.body.secret;

	User.findById(req.user.id)
	.then((foundUser) => {
		if (foundUser) {
			foundUser.secret = submittedsecret;
			foundUser.save()
			.then(()=>{
				res.redirect("/secrets");
			})
			.catch((err)=> {
				console.log(err);
			});
		}
	})
	.catch((err) => {
		console.log(err);
	});
});

///////////////// LISTEN /////////////////

app.listen(process.env.PORT||3000, function() {
	console.log("Server started on port 3000");
});