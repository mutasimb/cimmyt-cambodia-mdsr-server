const
  express = require("express"),
  { urlencoded, json } = require("body-parser"),
  { connect, set } = require("mongoose"),

  { mongoURI } = require("./config/keys.js"),

  app = express();


app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, x-auth-token");
  next();
});
app.use(urlencoded({ extended: false }));
app.use(json());


// routes
app.use("/api/users", require("./routes/users.js"));
app.use("/api/services", require("./routes/services.js"));


const
  port = process.env.PORT || 9001,
  serverInitiate = async () => {
    set('strictQuery', false);

    try {
      await connect(mongoURI);
      console.log('Successfully connected to MongoDB');

      await app.listen(port);
      console.log(`Server running on port ${port}`);
    } catch (error) {
      console.log('Failed to connect MongoDB', error);
    }
  };

serverInitiate();
