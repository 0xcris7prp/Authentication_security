import express from "express";
import bodyParser from "body-parser";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10;

app.set("view engine", "ejs");

const db = await mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Pranav@87',
  database: 'secrets',
  port: 3306,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});


app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const [checkResult] = await db.execute("SELECT * FROM USERS WHERE email = ?", [email]);

    if (checkResult.length > 0) {
      res.send("Email already exists. Try logging in or use a different email.");
    } else {
      // hashing passwords
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password:", err);
          res.status(500).send("Server Error");
        } else {
        const [result] = await db.execute(
        "INSERT INTO USERS (email, password) VALUES (?, ?)",
        [email, hash]
        );
        console.log("User inserted:", result);
        res.render("secrets.ejs");
      }
    });
  }
  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).send("Server Error");
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;

  try {
    console.log(`Attempting login with email: ${email}`);

    const [rows] = await db.execute("SELECT * FROM USERS WHERE email = ?", [email]);

    // Debugging output to check the results of the query
    // console.log(`Query result: ${JSON.stringify(rows)}`);

    if (rows.length > 0) {
      const user = rows[0];
      const dbHahsedPassword = user.password; //column name is 'password'

      bcrypt.compare(loginPassword, dbHahsedPassword, (err,result) =>{
        if (err) {
          console.log("error comparing password", err);
        } 
        
          if (result) {
          res.render("secrets.ejs");
          } else {
          res.send("Incorrect Username or Password.");
          }
        });
    } else {
      res.send("User Not Found.");
    }
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).send("Server Error");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
