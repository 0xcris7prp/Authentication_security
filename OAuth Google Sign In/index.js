import express, { query } from "express";
import bodyParser from "body-parser";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";


const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.set("view engine", "ejs");

const db = await mysql.createConnection({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  port: process.env.MYSQL_PORT,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave:false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.get("/secrets", (req,res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout((err) =>{
    if (err) console.log(err);
    res.redirect("/");
  });
});

//setting up passport middleware created at bottom
app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile", "email"] //to tell user what data we are going to get from 3rd party
}));

//steps to perform after user do google login action
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/login",passport.authenticate("local",{
  successRedirect: "/secrets",
  failureRedirect: "/login",
}));

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const [checkResult] = await db.execute("SELECT * FROM USERS WHERE email = ?", [email]);

    if (checkResult.length > 0) {
      res.send("Email already exists. Try logging in or use a different email.");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password:", err);
          res.status(500).send("Server Error");
        } else {

        const [result] = await db.execute(
        "INSERT INTO USERS (email, password) VALUES (?, ?)",
        [email, hash]
        );

        const [userResult] = await db.execute(
          "SELECT * FROM USERS WHERE ID = LAST_INSERT_ID()"
        );
        const user = userResult[0]; 
        req.login(user, (err) => {
          if (err) {
          console.error(err);
          res.status(500).send("server error.");
        }else {
          res.redirect("/secrets");
        }
      });
    }
  });
}
  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).send("Server Error");
  }
});


passport.use( new Strategy(async function verify(username,password, cb) {
  try {
    const [rows] = await db.execute("SELECT * FROM USERS WHERE email = ?", [username]);
    if (rows.length > 0) {
      const user = rows[0];
      const dbHahsedPassword = user.password; //column name is 'password'

      bcrypt.compare(password, dbHahsedPassword, (err,isValid) =>{
        //Error with password check
        if (err) {
          console.error("Error comparing passwords:", err);
          return cb(err);
        } 
          if (isValid) {

            return cb(null,user);
          } else {
 
            return cb(null,false);
          }
        });
    } else {
      return cb(err);
    }
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).send("Server Error");
  }
}))

//setting passport strategy for google login
passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async  (accessToken, refreshToken, profile, cb)=>{
  console.log(profile);
  //store data of user in our db after google login
  try{ //we want to store email of user, so we get that from profile
    const [result] = await db.query("SELECT * FROM USERS WHERE email=?", [profile.email]);
    //we want to check if email already prensent in db
    if (result.length === 0) { //user is not in db
      const [newUser] = await db.query("INSERT INTO USERS (email,password) VALUES(?,?)", [profile.email, "google"]);
      cb(null, newUser[0] );
    } else {
      //already exist
      cb(null, result[0]);
    }
  }catch (err) {
      cb(err);
  }
    } 
  )
);


passport.serializeUser((user,cb) => {
  cb(null,user);
});

passport.deserializeUser((user,cb) => {
  cb(null,user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
